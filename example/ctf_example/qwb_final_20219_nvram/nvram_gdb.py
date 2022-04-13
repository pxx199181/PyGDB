from PyGDB import PyGDB
from pwn import *

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

class BBLNode(object):
    """docstring for BBLNode"""
    def __init__(self, args):
        self.next_bbl   = args[0]
        self.jmp_pc     = args[1]
        self.handler    = args[2]
        self.pc         = args[3]
        

import hashlib
def md5sum(data):
    a = hashlib.md5()
    a.update(data)
    return a.hexdigest()

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

    binary_path = "nvram_exp"
    pygdb = PyGDB(target = binary_path)

    pygdb.start()
    pygdb.setvbuf0()
    #pygdb.dup_io_static(port = 12345)#, new_terminal = True)
    pygdb.dup_io(port = 12345)#, new_terminal = False)

    code_addr = 0x8304000
    data_addr = 0x8300000
    map_config = {
        data_addr:[0x1000, "rw"],
        code_addr:[0x2000, "wx"],
    }

    pygdb.init_map_config(map_config)
    use_addr = code_addr
    use_size = 0x1000

    use_addr = 0x403d58
    use_size = 0x404e10 - 0x403d58

    bin_elf = ELF(binary_path)

    pygdb.config_inject_map(use_addr, use_size, bin_elf.plt)

    in_data     = 'in addr: %p bbl_addr = %p\n\x00'
    out_data    = '|__out addr: %p bbl_addr = %p\n\x00'
    poke_data   = '  --poke data [%p -> %llx]\n\x00'
    in_addr     = pygdb.inject_hook_alloc(in_data)
    out_addr    = pygdb.inject_hook_alloc(out_data)
    poke_addr     = pygdb.inject_hook_alloc(poke_data)
    
    asm_code = """
    push rax
    push rax
    mov  rsi, QWORD PTR [rbp-0x200]
    ;dec rsi
    mov  rdx, cs:0x604a00
    mov  rdi, 0x%x
    call printf
    pop rax
    pop rax
    """%(in_addr)
    in_hook_addr = pygdb.inject_hook(0x401833, asm_code, show = True)

    
    asm_code = """
    mov  rdi, 0x%x
    mov  rsi,QWORD PTR [rbp-0x1E8]
    mov  rax, cs:0x604a00
    mov  rdx,QWORD PTR [rax+0x18]
    call printf
    """%(poke_addr)
    poke_hook_addr = pygdb.inject_hook(0x4019DF, asm_code, show = True)

    asm_code = """
    mov  rdi, 0x%x
    mov  rsi,QWORD PTR [rbp-0x200]
    mov  rdx, cs:0x604a00
    call printf
    """%(out_addr)
    out_hook_addr = pygdb.inject_hook(0x401B94, asm_code, show = True)

    
    pygdb.inject_into_file(binary_path, binary_path + "_in", bin_elf.address)
    """
    print("all")
    pygdb.show_inject_info()
    print("-"*0x10)

    pygdb.clear_inject_patch()
    print("after clear_inject_patch")
    pygdb.show_inject_info()
    print("-"*0x10)

    pygdb.inject_hook_free(in_addr, len(in_data))
    pygdb.inject_hook_free(out_addr)
    pygdb.inject_hook_free(poke_addr, len(out_data))

    print("after release")
    pygdb.show_inject_info()
    print("-"*0x10)
    #"""
    pygdb.clear_inject_hook()

    pygdb.inject_patch_asm(0x403722, "mov eax, 0x0")
    pygdb.inject_patch_asm(0x40147C, "mov eax, 0x1")

    #pygdb.interact()
    #init handler
    pygdb.run_until(0x400C07)


    def hook_catch_syscall(pygdb, bpType, syscall_name):
        if bpType == "OnEnter":
            #print("call %s()"%(syscall_name))
            if syscall_name == "read":
                rdi = pygdb.get_reg("rdi")
                rsi = pygdb.get_reg("rsi")
                rdx = pygdb.get_reg("rdx")
                print("call %s(0x%x, 0x%x, 0x%x)"%(syscall_name, rdi, rsi, rdx))
                #pygdb.interact()
            elif syscall_name == "write":
                rdi = pygdb.get_reg("rdi")
                rsi = pygdb.get_reg("rsi")
                rdx = pygdb.get_reg("rdx")
                data = pygdb.read_mem(rsi, rdx)
                print("call %s(0x%x, %s, 0x%x)"%(syscall_name, rdi, repr(data), rdx))
            else:
                print("call %s()"%(syscall_name))

    pygdb.hook_catch_syscall("", hook_catch_syscall, [])

    def hook_plt(pygdb, bpType, name):
        if bpType == "OnEnter":            
            if name in ["read", "write"]:
                return
            rdi = pygdb.get_reg("rdi")
            rsi = pygdb.get_reg("rsi")
            rdx = pygdb.get_reg("rdx")
            if name == "strncmp":
                str1 = pygdb.readString(rdi)
                str2 = pygdb.readString(rsi)
                print("call %s(%s, %s, %d)"%(name, repr(str1), repr(str2), rdx))
            elif name in ["strlen", "printf"]:
                str1 = pygdb.readString(rdi)
                print("call %s(%s)"%(name, repr(str1)))
            else:
                print("call %s()"%name)


    for key in bin_elf.plt.keys():
        addr = bin_elf.plt[key]
        pygdb.hook(addr, hook_plt, [key])

    def hook_malloc(pygdb, bpType, name):
        if bpType == "OnEnter":
            pygdb.globals["size"] = pygdb.get_reg("rdi")
            print("before %s"%name)
            pygdb.heapinfo()
        elif bpType == "OnRet":
            rax  = pygdb.get_reg("rax")
            size = pygdb.globals["size"]
            print("after %s"%name)
            print("%s(0x%x) = 0x%x"%(name, size, rax))
            pygdb.heapinfo()

    def hook_free(pygdb, bpType):
        if bpType == "OnEnter":
            addr = pygdb.get_reg("rdi")
            print("free(0x%x)"%(addr))
        elif bpType == "OnRet":
            pygdb.heapinfo()

    #pygdb.setHeapFilter("fastbin|tcache|unsortbin")
    data = pygdb.execute("print &main_arena")
    print "data:", repr(data)

    libc_elf = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc_elf.address = pygdb.libc()

    pygdb.hook(libc_elf.symbols["malloc"], hook_malloc, ["malloc"], hook_ret = True)
    pygdb.hook(libc_elf.symbols["calloc"], hook_calloc, ["calloc"], hook_ret = True)
    pygdb.hook(libc_elf.symbols["free"],   hook_free, [], hook_ret = True)

    bbl_ptr = 0x604A20
    ins_map = {}

    regs_addr = data_addr

    ins_args = pygdb.read_long_list(bbl_ptr, 139*4)

    for i in range(0, 139*4, 4):
        ins_map[bbl_ptr] = BBLNode(ins_args[i:i+4])
        bbl_ptr += 0x20

    def trans_regs(regs_map):
        regs = [0]*28
        for i in range(15, 11, -1):
            regs[15 - i] = regs_map["r%d"%i]
        regs[4] = regs_map["rbp"]
        regs[5] = regs_map["rbx"]
        for i in range(11, 7, -1):
            regs[11 - i + 6] = regs_map["r%d"%i]
        regs[10] = regs_map["rax"]
        regs[11] = regs_map["rcx"]
        regs[12] = regs_map["rdx"]
        regs[13] = regs_map["rsi"]
        regs[14] = regs_map["rdi"]

        regs[15] = regs_map["rax"]
        regs[16] = regs_map["rip"]

        regs[17] = regs_map["cs"]
        regs[18] = regs_map["eflags"]
        regs[19] = regs_map["rsp"]
        regs[20] = regs_map["ss"]
        return regs

    show = raw_input("show details?(1:yes, 0:no): ").strip()
    if show == "1":
    	show = True
    else:
    	show = False
    bbl_ptr = 0x604A20
    stack_array = [0]*51
    stack_idx = 0
    while True:
        status = 1
        pc, msg = pygdb.Continue(syn = True)
        while pc == -1:
        	#pygdb.do_pygdb_syn()
        	pygdb.interact_pygdb()
        	pc, msg = pygdb.Continue(syn = True)

        pc = pygdb.get_reg("pc")
        sp = pygdb.get_reg("sp")
        
        if show:
        	print("in addr: 0x%x bbl_addr = 0x%x"%(pc, bbl_ptr))

        if bbl_ptr in ins_map.keys():
            cur_BBLNode = ins_map[bbl_ptr]
        else:
            print("error")
            break
        if cur_BBLNode.handler != 0:
            #print(hex(pc), "handler -> ", hex(cur_BBLNode.handler))
            regs_map = pygdb.get_regs()
            regs = trans_regs(regs_map)
            #regs[16] = pc
            #regs[19] = sp
            #eflags = pygdb.get_reg("eflags")
            #regs[18] = eflags
            pygdb.write_long_list(regs_addr, regs)
            
            sp_data = pygdb.read_mem(sp, 0x100)
            hash1 = md5sum(sp_data)
            if show:
            	print("call handler 0x%x"%cur_BBLNode.handler)
            args = [regs_addr]
            deal_idx = pygdb.call_s(cur_BBLNode.handler, args = args)

            regs_new = pygdb.read_long_list(regs_addr, 28)
            for i in range(28):
                if regs_new[i] != regs[i]:
                    print("call handler 0x%x -> reg[%d]: 0x%x -> 0x%x"%(cur_BBLNode.handler, i, regs_new[i], regs[i]))

            pc = regs[16]
            sp = regs[19]

            sp_data = pygdb.read_mem(sp, 0x100)
            hash2 = md5sum(sp_data)

            #print(hash1 == hash2, hash1)
            if hash1 != hash2:
                print("got it")
                pygdb.interact()

            #print("handler, res = >", deal_idx)
            #print(hex(eflags), deal_idx)
            if deal_idx == 1:                
                #print(hex(pc), "handler go next")
                #print(hex(pc), "go next" -> hex(cur_BBLNode.jmp_pc))
                bbl_ptr = cur_BBLNode.jmp_pc
            elif deal_idx == 2:
                stack_idx -= 1
                bbl_ptr = stack_array[stack_idx]
                sp += 8
                #print("ret")
            elif deal_idx == 3:
                origin_pc = pc
                pc = cur_BBLNode.jmp_pc
                bbl_ptr = cur_BBLNode.next_bbl
                sp -= 8
                if show:
                	print("--poke data [0x%x -> 0x%x]"%(sp, ins_map[bbl_ptr].pc))
                pygdb.write_long(sp, ins_map[bbl_ptr].pc)
                status = 0
                #print("call to", hex(pc), "ret to -> ", hex(ins_map[bbl_ptr].pc))
            elif deal_idx == 4:
                if stack_idx > 48:
                    print("exit")
                    break
                stack_array[stack_idx] = cur_BBLNode.next_bbl
                stack_idx += 1
                sp -= 8
                bbl_ptr = cur_BBLNode.jmp_pc
            elif deal_idx == 5: 
                if stack_idx > 8:
                    print("exit")
                    break
                stack_array[stack_idx] = cur_BBLNode.next_bbl
                stack_idx += 1
                sp -= 8
                find_sign = False
                for addr in ins_map.keys():
                    if ins_map[addr].pc == pc:
                        bbl_ptr = addr
                        find_sign = True
                        break
                if find_sign == False:
                    print("exit")
                    break  
                status = 0
            elif deal_idx == 0:
                bbl_ptr = cur_BBLNode.next_bbl
        else:
            #print(hex(pc), "go next ->", hex(cur_BBLNode.jmp_pc))
            bbl_ptr = cur_BBLNode.jmp_pc

        if status:
            pc = ins_map[bbl_ptr].pc
        if show:
        	print("|__out addr: 0x%x bbl_addr = 0x%x"%(pc, bbl_ptr))
        pygdb.set_reg("sp", sp) 
        pygdb.set_reg("pc", pc) 

        """
        def trace_handler(pygdb, pc):
            asmCode = pygdb.get_disasm(pc, 1)[0]
            pygdb.context_code(4)
            pygdb.context_stack(4)
            if asmCode[1] == "syscall":
                return "end"
        if pc == 0x400a60:
            #pygdb.trace(pc, trace_handler = trace_handler)
            pygdb.interact()
        """
    pygdb.detach()
    exit(0)

if __name__ == "__main__":
    main()