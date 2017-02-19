package main

import (
    //"bytes"
    //"debug/elf"
    //"encoding/binary"
    //"encoding/hex"
    "fmt"
    "os"
    "syscall"
)

func goose_loop(pid int, got *heap_functions_got) int {
    var breakpoints map[uintptr]*breakpoint =
        make(map[uintptr]*breakpoint)
    //var allocd_bufs map[uintptr]*allocated_buffer =
    //    make(map[uintptr]*allocated_buffer)

    /* Set breakpoints on calloc(), malloc(), realloc(), free() */
    for i := CALLOC; i <= FREE; i++ {
        if got.addrs[i] == 0{
            continue
        }
        var bp *breakpoint = new(breakpoint)
        init_breakpoint(pid, got.addrs[i], bp)
        bp.index = i
        breakpoints[got.addrs[i]] = bp
        set_breakpoint(pid, bp)
    }

    var regset syscall.PtraceRegs
    var status int
    status = child_continue(pid, &regset)
    /* Loop: dynamic address not yet resolved */
    for {
        if status != 0 {
            if status == 2 {
                return 0
            }
            return 1
        }
        /* Subtract 1 from Rip */
        regset.Rip--
        var bp_addr uintptr = uintptr(regset.Rip)
        var bp *breakpoint = breakpoints[bp_addr]

        /* Get return address */
        var rsp uintptr = uintptr(regset.Rsp)
        var return_addr uintptr = uintptr(ptrace_read(pid, rsp))

        /* Single step past breakpoint*/
        breakpoint_step(pid, bp, &regset)

        /* Get function args */
        var rdi, rsi uint64 = regset.Rdi, regset.Rsi

        var bp_ret breakpoint
        switch(bp.index) {
        case CALLOC:
            fmt.Printf("calloc(%d, %d)\n", rdi, rsi)
            /* Break on return address */
            init_breakpoint(pid, return_addr, &bp_ret)
            set_breakpoint(pid, &bp_ret)
            status = child_continue(pid, &regset)
            if status != 0 {
                return 1
            }
            regset.Rip--
            breakpoint_step(pid, &bp_ret, &regset)
            /* child has returned from function */
            if !got.resolved[CALLOC] {
                /* Read in new address */
                delete(breakpoints, bp_addr)
                got.addrs[CALLOC] = uintptr(ptrace_read(pid, got.got_offsets[CALLOC]))
                init_breakpoint(pid, got.addrs[CALLOC], bp)
                breakpoints[got.addrs[CALLOC]] = bp
                got.resolved[CALLOC] = true
            }
        case MALLOC:
            /* Break on return address */
            init_breakpoint(pid, return_addr, &bp_ret)
            set_breakpoint(pid, &bp_ret)

            fmt.Printf("malloc(%d)\n", rdi)

            status = child_continue(pid, &regset)
            if status != 0 {
                return 1
            }
            regset.Rip--
            breakpoint_step(pid, &bp_ret, &regset)

            if !got.resolved[MALLOC] {
                /* Read in new address */
                delete(breakpoints, bp_addr)
                got.addrs[MALLOC] = uintptr(ptrace_read(pid, got.got_offsets[MALLOC]))
                init_breakpoint(pid, got.addrs[MALLOC], bp)
                breakpoints[got.addrs[MALLOC]] = bp
                got.resolved[MALLOC] = true
            }
        case REALLOC:
            /* Break on return address */
            init_breakpoint(pid, return_addr, &bp_ret)
            set_breakpoint(pid, &bp_ret)

            fmt.Printf("realloc(0x%016x, %d)\n", rdi, rsi)
            status = child_continue(pid, &regset)
            if status != 0 {
                return 1
            }
            regset.Rip--
            breakpoint_step(pid, &bp_ret, &regset)
            if !got.resolved[REALLOC] {
                /* Read in new address */
                delete(breakpoints, bp_addr)
                got.addrs[REALLOC] = uintptr(ptrace_read(pid, got.got_offsets[REALLOC]))
                init_breakpoint(pid, got.addrs[REALLOC], bp)
                breakpoints[got.addrs[REALLOC]] = bp
                got.resolved[REALLOC] = true
            }

        case FREE:
            fmt.Printf("free(0x%016x)\n", rdi)
            /* If symbol not resolved by dynamic linker/loader, break on return address */
            if !got.resolved[FREE] {
                 /* Break on return address */
                init_breakpoint(pid, return_addr, &bp_ret)
                set_breakpoint(pid, &bp_ret)
                status = child_continue(pid, &regset)
                if status != 0 {
                    return 1
                }
                regset.Rip--
                breakpoint_step(pid, &bp_ret, &regset)
                delete(breakpoints, bp_addr)
                got.addrs[FREE] = uintptr(ptrace_read(pid, got.got_offsets[FREE]))
                init_breakpoint(pid, got.addrs[FREE], bp)
                breakpoints[got.addrs[FREE]] = bp
                got.resolved[FREE] = true
            }
        default:
            fmt.Printf("Unrecognized Breakpoint: 0x%016x\n", bp_addr)
            return 1
        }
        set_breakpoint(pid, bp)
        status = child_continue(pid, &regset)
    }
    return 0
}

func main() {
    os.Exit(main_c(os.Args))
}

func main_c(argv []string) int {
    if len(argv) < 2 {
        fmt.Fprintf(os.Stderr, "Usage: %s <executable + arguments>\n", argv[0])
        return 1;
    }

    /* Child process needs to be ptraced */
    var proc_attr syscall.ProcAttr
    var sys_attr syscall.SysProcAttr
    proc_attr.Files = []uintptr{
        uintptr(syscall.Stdin),
        uintptr(syscall.Stdout),
        uintptr(syscall.Stderr),
    }
    //proc_attr.Env = syscall.Environ()

    sys_attr.Ptrace = true
    proc_attr.Sys = &sys_attr

    var got heap_functions_got = heap_functions_got{
        [4]uintptr{0, 0, 0, 0},
        [4]uintptr{0, 0, 0, 0},
        [4]bool{false, false, false, false},
    }
    var err_code int = inspect_elf(argv[1], &got)

    if err_code != 0 {
        fmt.Printf("ELF error\n")
        return 1
    }

    var status syscall.WaitStatus
    var rusage syscall.Rusage
    var child_pid, pid int
    var err error

    child_pid, err = syscall.ForkExec(argv[1], argv[1:], &proc_attr)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Fork + exec failure\n")
        return 1
    }

    pid, err = syscall.Wait4(pid, &status, 0, &rusage)
    if child_pid != pid {
        fmt.Fprintf(os.Stderr, "I declare shenanigans!\n")
        return 1
    }

    fmt.Printf("Child pid: %d\n", child_pid)
    Read_got(child_pid, &got)
    return goose_loop(child_pid, &got)

    return 0;
}
