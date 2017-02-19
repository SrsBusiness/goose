package main

import (
    "bytes"
    "debug/elf"
    "encoding/binary"
    "fmt"
    "os"
    "syscall"
)

type HEAP_FUNCTION uint32

const (
    CALLOC      = 0
    MALLOC      = 1
    REALLOC     = 2
    FREE        = 3
)

type heap_functions_got struct {
    got_offsets     [4]uintptr
    addrs           [4]uintptr
    resolved        [4]bool
}

type GOOSE_ERROR_TYPE uint32

const (
    ELF_VERSION_ERROR           = 0
    ELF_CLASS_ERROR             = 1
    ELF_TYPE_ERROR              = 2
    ELF_ARCH_ERROR              = 3
    ELF_SECTION_TYPE_ERROR      = 4
)

type GOOSE_ERROR struct {
    Type GOOSE_ERROR_TYPE
    Message string
}

func heap_summary(allocd_bufs *map[uintptr]*allocated_buffer, invalid_frees *[]*allocated_buffer) int {
    if len(*allocd_bufs) == 0 && len(*invalid_frees) == 0 {
        fmt.Printf("No memory errors!\n")
    }
    for addr, buffer := range *allocd_bufs {
        fmt.Printf("Leaked buffer: 0x%016x of size %d\n", addr, buffer.size)
    }
    for _, buffer := range *invalid_frees {
        fmt.Printf("Invalid free on address 0x%016x\n", buffer.addr)
    }
    return 0
}

func read_got(pid int, got *heap_functions_got) int {
    for i := CALLOC; i <= FREE; i++ {
        if got.got_offsets[i] == 0 {
            continue
        }
        var bytes [8]byte
        var bytes_read int
        var err error
        bytes_read, err = syscall.PtracePeekText(pid, got.got_offsets[i], bytes[:])
        if bytes_read != 8 || err != nil {
            fmt.Fprintf(os.Stderr, "Ptrace read error\n")
            return 1
        }
        got.addrs[i] = uintptr(ptrace_read(pid, got.got_offsets[i]))
    }
    return 0
}

type breakpoint struct {
    addr            uintptr
    addr_aligned    uintptr
    original_code   [8]byte
    new_code        [8]byte
    allocd_buf      *allocated_buffer
    index           int
}

type allocated_buffer struct {
    addr    uintptr
    size    uint64
}

const INT3 byte = 0xcc

func init_breakpoint(pid int, addr uintptr, bp *breakpoint) int {
    bp.addr = addr
    var num_bytes int
    var err error

    /* 
     * We can only read in 8-byte words at a time, so addresses have to be
     * aligned
     */
    bp.addr_aligned = bp.addr &^ uintptr(0x7)

    /* Save original code */
    num_bytes, err = syscall.PtracePeekText(pid, bp.addr_aligned, bp.original_code[:])
    if num_bytes != 8 || err != nil {
        fmt.Fprintf(os.Stderr, "Ptrace read error\n")
        return 1
    }

    /* INT3 instruction */
    bp.new_code = bp.original_code
    bp.new_code[bp.addr - bp.addr_aligned] = INT3
    return 0
}

func set_breakpoint(pid int, bp *breakpoint) int {
    var num_bytes int
    var err error

    num_bytes, err = syscall.PtracePokeText(pid, bp.addr_aligned, bp.new_code[:])
    if num_bytes != 8 || err != nil {
        fmt.Fprintf(os.Stderr, "Ptrace write error\n")
        return 1
    }
    return 0
}

func clear_breakpoint(pid int, bp *breakpoint) int {
    var num_bytes int
    var err error

    /* restore orignal code, then resume */
    num_bytes, err = syscall.PtracePokeText(pid, bp.addr_aligned, bp.original_code[:])
    if num_bytes != 8 || err != nil {
        fmt.Fprintf(os.Stderr, "Error writing to child process memory\n")
        return 1
    }
    return 0
}

func print_regset(regset *syscall.PtraceRegs) {
    fmt.Printf("R15     : 0x%016x\n", regset.R15     )
    fmt.Printf("R14     : 0x%016x\n", regset.R14     )
    fmt.Printf("R13     : 0x%016x\n", regset.R13     )
    fmt.Printf("R12     : 0x%016x\n", regset.R12     )
    fmt.Printf("Rbp     : 0x%016x\n", regset.Rbp     )
    fmt.Printf("Rbx     : 0x%016x\n", regset.Rbx     )
    fmt.Printf("R11     : 0x%016x\n", regset.R11     )
    fmt.Printf("R10     : 0x%016x\n", regset.R10     )
    fmt.Printf("R9      : 0x%016x\n", regset.R9      )
    fmt.Printf("R8      : 0x%016x\n", regset.R8      )
    fmt.Printf("Rax     : 0x%016x\n", regset.Rax     )
    fmt.Printf("Rcx     : 0x%016x\n", regset.Rcx     )
    fmt.Printf("Rdx     : 0x%016x\n", regset.Rdx     )
    fmt.Printf("Rsi     : 0x%016x\n", regset.Rsi     )
    fmt.Printf("Rdi     : 0x%016x\n", regset.Rdi     )
    fmt.Printf("Orig_rax: 0x%016x\n", regset.Orig_rax)
    fmt.Printf("Rip     : 0x%016x\n", regset.Rip     )
    fmt.Printf("Cs      : 0x%016x\n", regset.Cs      )
    fmt.Printf("Eflags  : 0x%016x\n", regset.Eflags  )
    fmt.Printf("Rsp     : 0x%016x\n", regset.Rsp     )
    fmt.Printf("Ss      : 0x%016x\n", regset.Ss      )
    fmt.Printf("Fs_base : 0x%016x\n", regset.Fs_base )
    fmt.Printf("Gs_base : 0x%016x\n", regset.Gs_base )
    fmt.Printf("Ds      : 0x%016x\n", regset.Ds      )
    fmt.Printf("Es      : 0x%016x\n", regset.Es      )
    fmt.Printf("Fs      : 0x%016x\n", regset.Fs      )
    fmt.Printf("Gs      : 0x%016x\n", regset.Gs      )
}

func resolve_address(pid int,
        bp_addr uintptr,
        got *heap_functions_got,
        got_index int,
        bp *breakpoint,
        breakpoints *map[uintptr]*breakpoint) {
    delete(*breakpoints, bp_addr)
    got.addrs[got_index] = uintptr(ptrace_read(pid, got.got_offsets[got_index]))
    init_breakpoint(pid, got.addrs[got_index], bp)
    (*breakpoints)[got.addrs[got_index]] = bp
    got.resolved[got_index] = true
}

func return_from_function(pid int, return_addr uintptr, bp_ret *breakpoint, regset *syscall.PtraceRegs) int {
    init_breakpoint(pid, return_addr, bp_ret)
    set_breakpoint(pid, bp_ret)
    var status int = child_continue(pid, regset)
    if status != 0 {
        return 1
    }
    return 0
}

func breakpoint_step(pid int, bp *breakpoint, regset *syscall.PtraceRegs) int {
    var err error

    clear_breakpoint(pid, bp)

    /* Reset Rip to the address of the interrupted instruction  */
    regset.Rip = uint64(bp.addr)
    err = syscall.PtraceSetRegs(pid, regset)

    /* Single Step. wait for child to stop */
    err = syscall.PtraceSingleStep(pid)
    var status syscall.WaitStatus
    var rusage syscall.Rusage
    var wpid int
    wpid, err = syscall.Wait4(pid, &status, 0, &rusage)
    if wpid != pid || err != nil {
        fmt.Fprintf(os.Stderr, "Wait error\n")
        return 1
    }
    if ! status.Stopped() {
        fmt.Fprintf(os.Stderr, "Error: child not stopped1\n")
        return 1
    }

    return 0
}

func child_continue(pid int, regset *syscall.PtraceRegs) int {
    /* Resume child process */
    var err = syscall.PtraceCont(pid, int(syscall.SIGCONT))
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error resuming child\n")
        return 1
    }

    var status syscall.WaitStatus
    var rusage syscall.Rusage
    var wpid int
    wpid, err = syscall.Wait4(pid, &status, 0, &rusage)
    if wpid != pid || err != nil {
        fmt.Fprintf(os.Stderr, "Wait error\n")
        return 1
    }
    if ! status.Stopped() {
        if status.Exited() {
            fmt.Fprintf(os.Stderr, "Child exited %d\n", status.ExitStatus())
            return 2;
        }
        fmt.Fprintf(os.Stderr, "Error: child not stopped1\n")
        return 1
    }

    /* Get registers */
    err = syscall.PtraceGetRegs(pid, regset)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error getting child registers\n")
        return 1
    }


    return 0
}

func ptrace_read(pid int, addr uintptr) uint64 {
    var bytes [8]byte
    syscall.PtracePeekText(pid, addr, bytes[:])
    return binary.LittleEndian.Uint64(bytes[:])
}

/* TODO: return error instead of integer status */
/* TODO: Stricter checking of types */
func inspect_elf(fname string, offsets *heap_functions_got) int {
    var f *elf.File
    var err error
    f, err = elf.Open(fname)
    if err != nil || f == nil {
        fmt.Fprintf(os.Stderr, "Fork + exec failure\n")
        return 1;
    }

    /*
     * .RELA.PLT SECTION
     */
    var rela_plt *elf.Section = f.Section(".rela.plt")
    if rela_plt.Type != elf.SHT_RELA {
        return 1;
    }

    /* 
     * .DYNSYM SECTION
     * Section header for '.rela.plt' contains a field called 'link',
     * which points to the dynsym section
     */
    var dynsym_index uint32 = rela_plt.Link

    var dynsym *elf.Section = f.Sections[dynsym_index]
    if dynsym.Type != elf.SHT_DYNSYM {
        return 1;
    }
    var dynsym_data []byte
    dynsym_data, err = dynsym.Data()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading .dynsym section\n")
    }

    var dynsym_reader *bytes.Reader = bytes.NewReader(dynsym_data)
    var dynsym_num_entries uint64 = dynsym.Size/dynsym.Entsize
    var dynsym_entries []elf.Sym64 = make([]elf.Sym64, dynsym_num_entries, dynsym_num_entries)
    binary.Read(dynsym_reader, f.ByteOrder, dynsym_entries[:])

    /* 
     * .DYNSTR SECTION
     * dynsym's link points to the dynstr section
     */
    var dynstr_index uint32 = dynsym.Link
    var dynstr *elf.Section = f.Sections[dynstr_index]
    if dynstr.Type != elf.SHT_STRTAB {
        return 1;
    }
    var dynstr_data []byte
    dynstr_data, err = dynstr.Data()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading .dynstr section\n")
    }

    /* Search for the Global PLT offsets for calloc(), malloc(), realloc(), free() */
    var plt_data []byte
    plt_data, err = rela_plt.Data()

    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading .rela.plt section\n")
    }

    var b_reader *bytes.Reader = bytes.NewReader(plt_data)
    var plt_entry elf.Rela64

    for b_reader.Len() > 0 {
        binary.Read(b_reader, f.ByteOrder, &plt_entry)
        var got_offset uint64 = plt_entry.Off
        var dynsym_index uint32 = elf.R_SYM64(plt_entry.Info)
        var dynstr_offset uint32 = dynsym_entries[dynsym_index].Name
        var null_index uint32 =
            uint32(bytes.IndexByte(dynstr_data[dynstr_offset:], 0)) + dynstr_offset
        var symbol_name string = string(dynstr_data[dynstr_offset:null_index])

        /* Phew, we finally have what we wanted! The symbol name and the GOT offset */
        switch symbol_name {
        case "calloc":
            offsets.got_offsets[CALLOC] = uintptr(got_offset)
        case "malloc":
            offsets.got_offsets[MALLOC] = uintptr(got_offset)
        case "realloc":
            offsets.got_offsets[REALLOC] = uintptr(got_offset)
        case "free":
            offsets.got_offsets[FREE] = uintptr(got_offset)
        default:
            continue
        }
    }

    f.Close()
    return 0
}
