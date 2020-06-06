from PyGDB import PyGDB

def test():
    target = "/bin/ls"
    pygdb = PyGDB(target)

    #pygdb.attach_name(target, 0)
    #pygdb.attach("ip:port")
    #pygdb.attach(pid)
    pygdb.start()

    print pygdb.get_regs()
    print pygdb.get_code()
    print pygdb.get_stack()
    rsp = pygdb.get_reg("rsp")
    print pygdb.get_mem(rsp, 0x20)
    print pygdb.hexdump(rsp, 0x20)

    #pygdb = PyGDB(target = target)
    #pygdb.attach_name(target, 0)
    #code_base = pygdb.codebase()
    #pygdb.set_bp(0x12B2 + code_base)
    #pygdb.Continue()

    print pygdb.get_bp()

    pygdb.interact()

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

    binary_path = "note"
    pygdb = PyGDB(target = binary_path)
    pygdb.attach_name(binary_path, 0)
    #pygdb.interact()
    pygdb.setHeapFilter("fastbin|tcache|unsortbin")
    data = pygdb.execute("print &main_arena")
    print "data:", repr(data)
    pygdb.heapinfo()
    #pygdb.interact()

    data = pygdb.execute("x/10i $pc")
    print data

    pygdb.heapinfo()

    calloc_offset = 0x81a50
    calloc_ret_offset = 0x81C3D
    malloc_offset = 0x80c40

    #calloc_offset = 0x84d10
    #calloc_ret_offset = 0x81C3D
    #malloc_offset = 0x84130

    __libc_calloc_addr = calloc_offset + pygdb.libc()
    malloc_addr = malloc_offset + pygdb.libc()
    print "malloc_addr:", hex(malloc_addr)
    print "__libc_calloc:", hex(__libc_calloc_addr)

    __libc_calloc_addr_ret = calloc_ret_offset + pygdb.libc()
    malloc_addr_ret = pygdb.find_ret(malloc_addr)
    print "__libc_calloc_ret:", hex(__libc_calloc_addr_ret)
    print "malloc_addr_ret:", hex(malloc_addr_ret)
    free_addr_ret = pygdb.find_ret("__libc_free")
    print "free_addr_ret:", hex(free_addr_ret)
    #pygdb.interact()


    pygdb.hook("__libc_free", hook_free, [], hook_ret = 0x7d20e+pygdb.libc())
    pygdb.hook(malloc_addr, hook_malloc, [], hook_ret = False)
    pygdb.hook(__libc_calloc_addr, hook_calloc, [], hook_ret = __libc_calloc_addr_ret)

    #pygdb.remove_hook(malloc_addr)
    #pygdb.remove_hook("__libc_free")
    #pygdb.interact()
    pygdb.Continue()
    
    pygdb.interact()

if __name__ == "__main__":
    main()