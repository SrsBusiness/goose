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
        var bp_addr uintptr = uintptr(regset.Rip - 1)
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
            return_from_function(pid, return_addr, &bp_ret, &regset)
            breakpoint_step(pid, &bp_ret, &regset)
            if !got.resolved[CALLOC] {
                resolve_address(pid, bp_addr, got, CALLOC, bp, &breakpoints)
            }
        case MALLOC:
            fmt.Printf("malloc(%d)\n", rdi)
            return_from_function(pid, return_addr, &bp_ret, &regset)
            breakpoint_step(pid, &bp_ret, &regset)
            if !got.resolved[MALLOC] {
                resolve_address(pid, bp_addr, got, MALLOC, bp, &breakpoints)
            }
        case REALLOC:
            fmt.Printf("realloc(0x%016x, %d)\n", rdi, rsi)
            return_from_function(pid, return_addr, &bp_ret, &regset)
            breakpoint_step(pid, &bp_ret, &regset)
            if !got.resolved[REALLOC] {
                resolve_address(pid, bp_addr, got, REALLOC, bp, &breakpoints)
            }
        case FREE:
            fmt.Printf("free(0x%016x)\n", rdi)
            if !got.resolved[FREE] {
                return_from_function(pid, return_addr, &bp_ret, &regset)
                breakpoint_step(pid, &bp_ret, &regset)
                resolve_address(pid, bp_addr, got, FREE, bp, &breakpoints)
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
