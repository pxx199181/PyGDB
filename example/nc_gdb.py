from PyGDB import PyGDB

def test():
    target = "/bin/ls"
    pygdb = PyGDB(target)
    pygdb.start()

    print(pygdb.get_regs())
    print(pygdb.get_code())
    print(pygdb.get_stack())
    rsp = pygdb.get_reg("rsp")
    print(pygdb.get_mem(rsp, 0x20))
    print(pygdb.hexdump(rsp, 0x20))

    print(pygdb.get_bp())

    pygdb.interact()

def main():
    use_port = 4444
    binary_path = "/bin/nc"
    pygdb = PyGDB(target = binary_path, args = [" -lvp", str(use_port)])
    #pygdb = PyGDB(target = binary_path, args = [" -6lvp", str(use_port)])
    #pygdb.attach_name(target, 0)
    #pygdb.attach("ip:port")
    #pygdb.attach(pid)

    pygdb.start()
    pygdb.setvbuf0_s()
    pygdb.dup_io_s(port = 12345, new_terminal = True)

    pc = pygdb.get_reg("pc")
    pc_ret = pygdb.find_ret(pc)
    print(hex(pc))
    print(hex(pc_ret))

    pygdb.set_bp("accept")
    pygdb.Continue()

    ret_addr = pygdb.get_backtrace(2)[1]
    print(pygdb.get_code(ret_addr, below = True, count = 10))
    pygdb.set_bp(ret_addr)

    rbp = pygdb.get_reg("rbp")
    pygdb.run_in_new_terminal("nc 0 %d"%use_port, sleep_time = 1)
    pygdb.Continue()

    fd = pygdb.get_reg("eax")
    info = pygdb.get_fd_info_s(fd)
    print("fd[%d]:"%fd, info)
    pygdb.Continue()

    pygdb.interact()
    exit(0)

if __name__ == "__main__":
    main()