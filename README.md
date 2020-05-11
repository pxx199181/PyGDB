# Outline
- Introduction
    - Feature
- Install
- Usage
    - Template
    - Basic
        - test x86/x64
        - test arm
        - test hook
        - test mmap
    - More
- Documention
- Update log
# Introduction
A gdb wrapper(based on `peda-arm`, modify some functions ) aiming at using python to debug.

need to install pwntools(if not use zio)

## Features

# Install
You need to install pwntools first.

git clone https://github.com/pxx199181/PyGDB/

`python setup.py install`
# Usage
## Template
Template for quick scripting.
```python
from PyGDB import PyGDB

def test():
    target_path = "/bin/ls"
    pygdb = PyGDB(target_path)

    #pygdb.attach_name(target_path, 0)
    #pygdb.attach("ip:port")
    #pygdb.attach(pid)
    pygdb.start()

    print pygdb.get_regs()
    print pygdb.get_code()
    print pygdb.get_stack()
    rsp = pygdb.get_reg("rsp")
    print pygdb.get_mem(rsp, 0x20)
    print pygdb.hexdump(rsp, 0x20)

    #pygdb = PyGDB(target_path = target_path)
    #pygdb.attach_name(target_path, 0)
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
    pygdb = PyGDB(target_path = binary_path)
    pygdb.attach_name(binary_path, 0)
    #pygdb.hook(0x8049318, hook_test, [pygdb, 0, 0x8049318, "call printf",])
    #pygdb.Continue()

    pygdb.set_bp(0x8049318)
    pygdb.Continue()

    pygdb.interact()

if __name__ == "__main__":
    main()

```
## Basic
test script

```python
from PyGDB import PyGDB

def test_intel():
    pygdb = PyGDB(target_path = "./test_x86")
    print(pygdb.set_bp(0x804861C))
    pygdb.start()
    print(pygdb.get_code(20))

    print(pygdb.hexdump(0x804861C, 0x21))
    print(pygdb.get_code(0x804861C, 20))
    #pygdb.attach("127.0.0.1:4444")
    print(pygdb.get_regs())
    print(pygdb.get_code())
    print(pygdb.get_stack())
    #pygdb.interact()
    print(pygdb.set_reg("eax", 0xdeadbeef))
    print(pygdb.stepi())
    print(pygdb.get_regs())
    print(pygdb.get_code())
    print(pygdb.get_stack())
    print("pyCmdRet read_mem 0x8048621 0x14")
    data = pygdb.get_mem(0x8048621, 20)
    #print("data:", data)
    for v in data:
        print(ord(v), type(v))

    print(pygdb.set_mem(0x8048621, "\x01"*0x10))
    data = pygdb.get_mem(0x8048621, 20)
    print("data:", data)

    print(pygdb.get_code(20))
    pygdb.interact()


def test_arm():
    pygdb = PyGDB(target_path = "./test_arm")
    pygdb.attach("127.0.0.1:4444")
    print(pygdb.set_bp(0x10474)) #jmp start_main
    print(pygdb.get_bp())
    print(pygdb.get_code(20))
    pygdb.Continue()
    print(pygdb.get_regs())
    print(pygdb.get_code())
    print(pygdb.get_stack())
    print(pygdb.stepi())
    print(pygdb.get_regs())
    print(pygdb.get_code())
    print(pygdb.get_stack())
    print("pyCmdRet read_mem 0x10630 0x14")

    sp = pygdb.get_reg("sp")
    print("sp:", hex(sp))
    data = pygdb.get_mem(sp, 20)
    #print("data:", data)
    for v in data:
        print(ord(v), type(v))

    print(pygdb.set_mem(sp, "\x01"*0x20))
    print(pygdb.set_reg("r0", 0xdeadbeef))
    data = pygdb.get_mem(sp, 20)
    print("data:", data)
    print(pygdb.hexdump(sp, 20))

    print(pygdb.get_code(20))
    print(pygdb.get_stack(20))
    pygdb.interact()

def test_hook():
    def hook_test(pygdb, id, addr, value):
        pc = pygdb.get_reg("pc")
        print("pc:", hex(pc))
        print("id--:", id)
        print("addr:", hex(addr))
        print("value:", value)

    def hook_out(pygdb, id, addr, value):
        pc = pygdb.get_reg("pc")
        print("pc:", hex(pc))
        print("id--:", id)
        print("addr:", hex(addr))
        print("value:", value)

        rbp = pygdb.get_reg("rbp")
        val = pygdb.read_int(rbp - 4)
        if val == 10:
            return False
        else:
            print("val:", val)

        if val == 4:
            pygdb.remove_hook(0x40054d)
        else:
            pass

        if val == 5:
            pygdb.remove_hook(0x400552)
        else:
            pass

    pygdb = PyGDB(target_path = "./test_hook")
    pygdb.hook(0x40054d, hook_test, [pygdb, 0, 0x40054d, "call printf",])
    pygdb.hook(0x400552, hook_out, [pygdb, 0, 0x400552, "cmp",])

    pygdb.start()

    #pygdb.Continue()
    #pygdb.clear_hook()
    #pygdb.stepi()

    #also can use Continue
    pygdb.run_until(0x400562)

    pygdb.interact()

def test_mmap():
    pygdb = PyGDB(target_path = "./test_hook")
    #pygdb.
    bp_id, bp_addr = pygdb.set_bp("main")
    #pygdb.interact()
    pygdb.start()
    pygdb.del_bp(bp_id)
    #print(pygdb.get_code(20))

    c_source = """
    void write_diy(int fd, char* data, int size);
    int strlen_diy(char *data);
    void upper_str(char *data, char val) {
        int len = strlen_diy(data);
        for(int i = 0; i < len; i++)
            if (data[i] > 0x20 && data[i] < 0x80) {
                data[i] |= val;
                data[i] -= 0x20;
            }
    }
    void print(void *data) {
        write_diy(1, data, strlen_diy(data));
    }
    void write_diy(int fd, char* data, int size) {
        __asm__(
        "mov $0x1, %eax\\t\\n"
        "syscall\\t\\n"
        );
    }
    int strlen_diy(char *data) {
        int i;
        for(i = 0; ; i++)
            if (data[i] == 0) 
                return i;
    }
    """
    code_data = pygdb.gen_payload(c_source, "upper_str")
    code_addr = 0x8304000
    data_addr = 0x8300000
    #print data.encode("hex")


    map_config = {
        data_addr:[0x1000, "rw"],
        code_addr:[0x2000, "wx"],
    }
    data_config = {
        data_addr:"welcome to use PyGDB", 
        code_addr:code_data, 
    }

    pygdb.init_map_config(map_config)
    pygdb.init_data_config(data_config)

    args = [data_addr, 0x20]
    pygdb.call(code_addr, args)

    str_info = pygdb.readString(data_addr)
    print str_info
    return


import sys
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "useage:"
        print "\t python test_pygdb.py intel/arm/hook/mmap"
    else:
        if sys.argv[1] == "intel":
            test_intel()
        elif sys.argv[1] == "arm":
            print "please run ./run_arm.sh first"
            test_arm()
        elif sys.argv[1] == "hook":
            test_hook()
        elif sys.argv[1] == "mmap":
            test_mmap()
```

### test x86/x64
test a x86/x64 case.

run 'python test_pygdb.py intel'

### test arm
test a arm case.

run './run_arm.sh' first

then run 'python test_pygdb.py arm'

### test hook
test hook demo.

run 'python test_pygdb.py hook'

### test mmap
test mmap demo.

run 'python test_pygdb.py mmap'

## More
read the code!

# Documention
TODO

# Update Log 
## 2019/12/15 Version 1.0.0
- release it