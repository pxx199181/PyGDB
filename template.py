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
    def hook_test(pygdb, id, addr, value):
        pc = pygdb.get_reg("pc")
        print("pc:", hex(pc))
        print("id:", id)
        print("addr:", hex(addr))
        print("value:", value)

    binary_path = "./binary"
    pygdb = PyGDB(target = binary_path)
    pygdb.attach_name(binary_path, 0)
    #pygdb.hook(0x8049318, hook_test, [pygdb, 0, 0x8049318, "call printf",])
    #pygdb.Continue()

    pygdb.set_bp(0x8049318)
    pygdb.Continue()

    pygdb.interact()

if __name__ == "__main__":
    main()