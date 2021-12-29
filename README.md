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
        - test patch
        - test dup_io
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
    target = "/bin/ls"
    pygdb = PyGDB(target)
    pygdb.start()

    print pygdb.get_regs()
    print pygdb.get_code()
    print pygdb.get_stack()
    rsp = pygdb.get_reg("rsp")
    print pygdb.get_mem(rsp, 0x20)
    print pygdb.hexdump(rsp, 0x20)

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
    #pygdb.attach_name(target, 0)
    #pygdb.attach("ip:port")
    #pygdb.attach(pid)
    pygdb.attach_name(binary_path, 0)
    pygdb.setHeapFilter("fastbin|tcache|unsortbin")
    data = pygdb.execute("print &main_arena")
    print "data:", repr(data)

    calloc_offset = 0x81a50
    calloc_ret_offset = 0x81C3D
    malloc_offset = 0x80c40

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
```
## Basic
test script

```python
from PyGDB import PyGDB

def test_intel():
    pygdb = PyGDB(target = "./test_x86")
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
    pygdb = PyGDB(target = "./test_arm")
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
    def hook_test(pygdb, bpType, id, addr, value):
        if bpType == "OnEnter":
            pc = pygdb.get_reg("pc")
            print("pc:", hex(pc))
            print("id--:", id)
            print("addr:", hex(addr))
            print("value:", value)

    def hook_out(pygdb, bpType, id, addr, value):
        if bpType == "OnEnter":
            pc = pygdb.get_reg("pc")
            print("pc:", hex(pc))
            print("id--:", id)
            print("addr:", hex(addr))
            print("value:", value)

            rbp = pygdb.get_reg("rbp")
            val = pygdb.read_int(rbp - 4)

            #rdi = pygdb.get_reg("rdi")
            rdi = rbp-4
            if pygdb.globals["only_once"] == False:
                print("*"*0x20)
                pygdb.globals["only_once"] = True
                pygdb.hook_mem_read(rdi, hook_mem_1)
                #pygdb.hook_mem_write(rdi, hook_mem_1)
                #pygdb.hook_mem_access(rdi, hook_mem_1)
                #pygdb.io.interactive()

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

    def hook_mem_1(pygdb, values):
        print("-"*0x20)
        print("values", [hex(c) for c in values])

    pygdb = PyGDB(target = "./test_hook")
    pygdb.hook(0x40054d, hook_test, [0, 0x40054d, "call printf",])
    pygdb.hook(0x400552, hook_out, [0, 0x400552, "cmp",])

    pygdb.globals["only_once"] = False

    pygdb.start()

    #pygdb.Continue()
    #pygdb.clear_hook()
    #pygdb.stepi()

    #also can use Continue
    pygdb.run_until(0x400562)

    print(hex(pygdb.get_lib_func("printf", "libc")))
    print(hex(pygdb.get_lib_func("puts")))

    shellcode = ""
    shellcode += asm(shellcraft.sh())


    pygdb.make_tiny_elf(shellcode, "test.bin", base = 0x400000)

    pygdb.interact()

from pwn import *
def test_mmap():
    pygdb = PyGDB(target = "./test_hook")
    #pygdb.
    bp_id, bp_addr = pygdb.set_bp("main")
    #pygdb.interact()
    pygdb.start()
    pygdb.del_bp(bp_id)
    #print(pygdb.get_code(20))
    #exit(0)

    context(arch = pygdb.arch, os = 'linux')
        
    open_code = pygdb.gen_inject_asm(shellcraft.open("rdi", "rsi", "rdx"))
    close_code = pygdb.gen_inject_asm(shellcraft.close("rdi"))
    filename = pygdb.gen_stack_value("filename", "./test\x00")
    endl = pygdb.gen_stack_value("endl", "\n\x00")
    c_source = """
    int write_diy(int fd, char* data, int size);
    int open_diy(char *filename, int md, int flag);
    int strlen_diy(char *data);
    void close_diy(int fd);
    gen_from_pwntools(int write(int fd, char* data, int size));
    gen_from_pwntools(int open(char* filename, int mode, int flag));
    int upper_str(char *data, char val) {
        char filename[10];
        %s
        char endl[16];
        %s
        int len = strlen_diy(data);
        //int fd = open(filename, 0666);
        int fd = open(filename, 0x42, 0755);
        write(fd, data, len);
        for(int i = 0; i < len; i++)
            if (data[i] > 0x20 && data[i] < 0x80) {
                data[i] |= val;
                data[i] -= 0x20;
            }
        write_diy(fd, endl, 1);
        write_diy(fd, data, len);
        close_diy(fd);
        return len;
    }
    int print(void *data) {
        return write_diy(1, data, strlen_diy(data));
    }
    int write_diy(int fd, char* data, int size) {
        __asm__(
        "mov $0x1, %%eax\\t\\n"
        "syscall\\t\\n"
        );
    }
    void close_diy(int fd) {
        %s
    }
    int strlen_diy(char *data) {
        int i;
        for(i = 0; ; i++)
            if (data[i] == 0) 
                return i;
    }
    """%(filename, endl, close_code)

    code_data = pygdb.gen_payload(c_source, "upper_str")#, obj_name = "uuu_obj")
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

    code_asm = pygdb.get_code(code_addr, 0x100)
    print "code_asm:"
    print code_asm
    code_asm = pygdb.get_code(0x830417e, 0x50)
    print "code_asm:"
    print code_asm
    
    def hook_count(pygdb, bpType, id, addr, value):
        #rdi = pygdb.
        if bpType == "OnEnter":
            pygdb.globals["count"] += 1
            if pygdb.globals["count"] > 5:
                pygdb.remove_hook(addr)
                del pygdb.globals["count"]
                return
            print "count", pygdb.globals["count"]

    pygdb.globals["count"] = 0
    #pygdb.hook(0x8304029, hook_count, [pygdb, 0, 0x8304029, "call 0x8304029",])

    #pygdb.set_bp(code_addr)
    ret_v = pygdb.call(code_addr, args)
    print "ret_v:", repr(ret_v), type(ret_v)
    print pygdb.globals

    str_info = pygdb.readString(data_addr)
    print str_info
    return

def test_patch():
    
    #pygdb = PyGDB(target = "./test_hook")
    pygdb = PyGDB(arch = "amd64")
    pygdb.writefile("test_patch", "SADKNJASNDKNSADNKJSANDSADKNJASNDKNSADNKJSANDSADKNJASNDKNSADNKJSAND")

    patch_config = {
        0 : "ni",
        4 : "wo",
        10 : "ha",
    }
    pygdb.patch_file("test_patch", patch_config, "test_patch.out")

    asm_info = """
    mov rax, rbx
    push rsp
    """
    patch_config = {
        0x400010 : "12",
        0x400020 : ["data", "33"],
        0x400024 : ["asm", asm_info],
    }
    pygdb.patch_file("test_patch.out", patch_config, base = 0x400000)


    pygdb = PyGDB()
    pygdb.load_source(arch = "amd64", text_addr = 0x8300000)
    pygdb.set_bp("main")
    pygdb.start()

    pygdb.interact()

    
def test_dup_io():
    def hook(pygdb, bpType):
        if bpType == "OnEnter":
            data = pygdb.get_regs()
            print data
            data = pygdb.get_code(count = 10)
            print data
            data = pygdb.get_stack(count = 20)
            print data

    pygdb = PyGDB(target = "./test_dup_io")
    b_id, _ = pygdb.set_bp("main")
    pygdb.run()
    pygdb.del_bp(b_id)

    pygdb.dup_io(port = 12345, new_terminal = True)
    #pygdb.dup_io(port = 12345, new_terminal = False)
    pygdb.hook(0x400883, hook, [])
    pygdb.Continue()
    #pygdb.detach()
    pygdb.interact()


import sys
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "useage:"
        print "\t python test_pygdb.py intel/arm/hook/mmap/patch/dup_io"
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
        elif sys.argv[1] == "patch":
            test_patch()
        elif sys.argv[1] == "dup_io":
            test_dup_io()
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

### test patch
test patch demo.

run 'python test_pygdb.py patch'

### test dup_io
test dup_io demo.

run 'python test_pygdb.py dup_io'

## More
read the code!

# Documention
TODO

# Update Log 
## 2019/12/15 Version 1.0.0
- release it
- python gdb wrapper

## 2020/05/13 Version 1.0.0
- add some useful function
- (1). mmap area
- (2). call func (valid, push str)
- (3). init map from config
- (4). init data from config
- (5). init data from file
- (6). gen shellcode from source(with pwntools)
- (7). patch file
- (8). patch asm mem
- (9). fix got table

## 2020/05/22 Version 1.0.0
- (1). call('symbol', args, lib_path = ..)
- (2). call(addr, args)
- (3). save_context / restore_context (only regs)
- (4). dup io to socket / or a new terminal

## 2020/05/26 Version 1.0.0
- (1). call_s safe call() -> save_context, call, restore_context 
- (2). interact(prompt) -> modify 
- (3). gdb_interact() -> interact with gdb in new terminal

## 2020/06/6 Version 1.0.0
- (1). merge angelheap(add gdb.execute func)
- (2). modify chunk print(set HeapFilter fastbin/smallbin/unsortbin/largebin/tcache/top_lastreminder)
- (3). modify hook function(search ret addr, OnEnter, OnRet)
- (4). modify `gdb file` for more debug info

## 2021/12/29 Version 1.0.0
- (1). add hook_mem_read/hook_mem_write/hook_mem_access func
- (2). add watch/awatch/rwatch func
- (3). remove some bugs

