from PyGDB import PyGDB
from pwn import *

def main():
    #test()
    def hook_malloc(pygdb, bpType):
        if bpType == "OnEnter":
            pygdb.globals["malloc_size"] = pygdb.get_reg("rdi")
        elif bpType == "OnRet":
            size = pygdb.globals["malloc_size"]
            addr = pygdb.get_reg("rax")
            print "malloc(0x%x) = 0x%x"%(size, addr)
            pygdb.heapinfo()
            print "*"*0x20
    
    def hook_calloc(pygdb, bpType):
        if bpType == "OnEnter":
            pygdb.globals["calloc_size"] = pygdb.get_reg("rsi")
        elif bpType == "OnRet":
            size = pygdb.globals["calloc_size"]
            addr = pygdb.get_reg("rax")
            print "calloc(0x%x) = 0x%x"%(size, addr)
            pygdb.heapinfo()
            print "*"*0x20
            #raw_input(":")

    def hook_free(pygdb, bpType):
        if bpType == "OnEnter":
            addr = pygdb.get_reg("rdi")
            print "free(0x%x)"%(addr)
        elif bpType == "OnRet":
            print "free over"
            pygdb.heapinfo()
            print "*"*0x20

    binary_path = "/bin/cat"
    pygdb = PyGDB(target = binary_path)
    #pygdb.attach_name(target, 0)
    #pygdb.attach("ip:port")
    #pygdb.attach(pid)
    #pygdb.attach_name(binary_path, 0)
    pygdb.start()

    code_addr = 0x100000000
    #print data.encode("hex")
    content = pygdb.readfile("./xor")
    code_data = content[0xCC0:0x1060]

    map_config = {
        code_addr:[0x2000, "wx"],
    }
    data_config = {
        code_addr + 0xCC0 : code_data, 
        code_addr + 0x1010: p64(code_addr + 0x1200),
    }

    pygdb.init_map_config(map_config)
    pygdb.init_data_config(data_config)

    got_list = []
    got_list.append(["memset",  0x100001028])
    got_list.append(["printf",  0x100001030])
    got_list.append(["read",    0x100001038])
    got_list.append(["exit",    0x100001020])
    got_list.append(["strlen",  0x100001040])
    got_list.append(["strncmp", 0x100001048])
    got_list.append(["__stack_chk_fail", 0x100001018])

    pygdb.fix_gots(got_list)

    pygdb.set_reg("pc", 0x100000D70)


    def hook_input(pygdb, bpType):
        if bpType == "OnEnter":
            rdi = pygdb.get_reg("rdi")
            rsi = pygdb.get_reg("rsi")

            pygdb.globals["rdi"] = rdi
            pygdb.globals["rsi"] = rsi
        elif bpType == "OnRet":
            rdi = pygdb.globals["rdi"]
            rsi = pygdb.globals["rsi"]

            if pygdb.globals["mode"] == 1:
                input_data = pygdb.readString(rdi)
                print("you input:", input_data)
                print("cheating")
                global_addr = 0x100000F6E
                data = pygdb.read_mem(global_addr, 33)
                pygdb.write_mem(rdi, data + "\x00")

                #pygdb.interact()

    def hook_strncmp(pygdb, bpType):
        if bpType == "OnEnter":
            rdi = pygdb.get_reg("rdi")
            rsi = pygdb.get_reg("rsi")
            rdx = pygdb.get_reg("rdx")
            rdiStr = pygdb.read_mem(rdi, 33)
            rsiStr = pygdb.read_mem(rsi, 33)
            print("strncmp(%x, %x, %d)"%((rdi), (rsi), rdx))
            print("strncmp(%s, %s, %d)"%(repr(rdiStr), repr(rsiStr), rdx))
            print(rdiStr == rsiStr)
            if pygdb.globals["mode"] == 1:
                rdiStr = "got flag is: " + rdiStr + "\n\x00"
                #data = data + "\n\x00"
                args = [rdiStr]
                pygdb.call_s("printf", args)#, debug_list = ["printf"])
            else:
                pass

    asm_code = pygdb.get_disasm(0x100000E0D)[0][1]
    print("asm_code:", asm_code)

    #print(pygdb.get_code(0x100000E0D))
    asm_code = asm_code.replace(",0x1", ",0x%x"%32)
    pygdb.inject_patch_asm(0x100000E0D, asm_code)
    #print(pygdb.get_code(0x100000E0D))

    asm_code = pygdb.get_disasm(0x100000E17)[0][1]
    print("asm_code:", asm_code)
    asm_code = asm_code.replace(",0x21", ",0x%x"%0)
    pygdb.inject_patch_asm(0x100000E17, asm_code)

    asm_code = pygdb.get_disasm(0x100000e1e)[0][1]
    print("asm_code:", asm_code)
    asm_code = "jl label\n"
    for i in range(0x6f - 0x1e - 2):
        asm_code += "nop\n"
    asm_code += "label:\n"

    context(arch = "amd64", os = "linux")
    data = asm(asm_code, vma = 0x100000e1e)
    print("data:", data)
    pygdb.inject_patch_data(0x100000e1e, data[:6])

    asm_code = "sub eax, 0x1"
    pygdb.inject_patch_asm(0x100000E61, asm_code)

    print(pygdb.get_code(0x100000E0D))

    def hook_syscall(pygdb, bpType, syscall_name, input_arg):
        if bpType == "OnEnter":
            pc = pygdb.get_reg("pc")
            #print(hex(pc), "enter", syscall_name)
            if syscall_name == "read":
                rdx = pygdb.get_reg("rdx")
                print("read - %s size"%input_arg, hex(rdx))
            else:
                print(syscall_name + " - %s"%input_arg)
        elif bpType == "OnRet":
            pc = pygdb.get_reg("pc")
            #print(hex(pc), "return", syscall_name)
            rax = pygdb.get_reg("rax")
            print("read ret %d"%(rax))

    pygdb.hook_catch_syscall("read", hook_syscall, ["read"])

    pygdb.setvbuf0_s()
    pygdb.dup_io_s(new_terminal = True)

    pygdb.hook(0x100000CC0, hook_input, [], hook_ret = True)
    pygdb.hook(0x100000f10, hook_strncmp, [])

    """
    b_addr = 0x100000DEB
    e_addr = 0x100000E89
    #function_mode = True
    function_mode = False
    trace_handler = None
    show = True
    #pygdb.trace(b_addr = b_addr, e_addr = e_addr, logPattern = "trace_log", byThread = True, asmCode = True, record_maps = [0x100000000, 0x100002000], trace_handler = trace_handler, function_mode = function_mode, show = show, oneThread = True)
    #pygdb.Continue()
    """

    mode = raw_input("mode?(1:crack, 0:check): ").strip()
    if mode == "0":
        pygdb.clear_inject_patch()
        print(pygdb.show_inject_info())
        pygdb.globals["mode"] = 0
        pygdb.set_bp("strncmp")
    else:
        print(pygdb.show_inject_info())
        pygdb.globals["mode"] = 1

    pygdb.Continue(syn = True)
    pygdb.interact_pygdb()
    #pygdb.interact()
    exit(0)

if __name__ == "__main__":
    main()