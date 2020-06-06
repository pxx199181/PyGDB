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

	pygdb = PyGDB(target = "./test_hook")
	pygdb.hook(0x40054d, hook_test, [0, 0x40054d, "call printf",])
	pygdb.hook(0x400552, hook_out, [0, 0x400552, "cmp",])

	pygdb.start()

	#pygdb.Continue()
	#pygdb.clear_hook()
	#pygdb.stepi()

	#also can use Continue
	pygdb.run_until(0x400562)

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
