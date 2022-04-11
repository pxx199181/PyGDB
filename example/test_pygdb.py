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

def test_inject_hook():

	pygdb = PyGDB(target = "./test_hook")
	#pygdb.hook(0x40054d, hook_test, [0, 0x40054d, "call printf",])
	#pygdb.hook(0x400552, hook_out, [0, 0x400552, "cmp",])

	pygdb.start()

	pygdb.setvbuf0()
	pygdb.dup_io(port = 12345, new_terminal = True)
	import time
	time.sleep(2)

	code_addr = 0x8304000
	data_addr = 0x8300000
	map_config = {
		data_addr:[0x1000, "rw"],
		code_addr:[0x2000, "wx"],
	}

	pygdb.init_map_config(map_config)

	globals_map = {}
	bin_elf = ELF("./test_hook")
	for key in bin_elf.plt.keys():
		globals_map[key] = bin_elf.plt[key]
	print("globals_map:", globals_map)
	pygdb.config_inject_map(code_addr, 0x1000, globals_map)

	#
	choice = raw_input("mode(patch to file?(1:yes, 0:no))").strip()
	if choice == "1":
		use_addr = 0x400460
		use_size  = 0x4004A0 - 0x400460
	else:
		use_addr = code_addr
		use_size = 0x1000
	#pygdb.config_inject_map(code_addr, 0x1000, globals_map)
	pygdb.config_inject_map(use_addr, use_size, globals_map)

	#pygdb.interact()

	message_data = "inject_hook\n\x00"
	data_addr = pygdb.inject_hook_alloc(message_data)
	asm_code = """
	push rdi
	push rsi
	mov rdi, 0x%x
	call printf
	pop rsi
	pop rdi
	"""%(data_addr)
	pygdb.inject_hook(0x40054d, asm_code)#, show = True)
	
	asm_code = "nop"
	pygdb.inject_hook(0x40055A, asm_code)

	pygdb.inject_patch_asm(0x4004ED, "nop")

	pygdb.run_until(0x400562)

	if choice == "1":
		pygdb.inject_into_file("./test_hook", "./test_hook_p", base = 0x400000)

	#pygdb.interact() # normal exit

	print("before remove_inject_hook")
	pygdb.show_inject_info()

	pygdb.remove_inject_hook(0x40054d)

	print("")
	print("after remove_inject_hook")
	pygdb.show_inject_info()


	pygdb.inject_hook_free(data_addr, len(message_data))
	print("")
	print("after inject_hook_free")
	pygdb.show_inject_info()

	pygdb.inject_restore(0x4004ED)
	print("")
	print("after inject_restore")
	pygdb.show_inject_info()

	pygdb.clear_inject_hook()
	print("")
	print("after clear_inject_hook")
	pygdb.show_inject_info()

	print("stage 2")
	pygdb.set_reg("pc", 0x0400526)
	pygdb.run_until(0x400562)

	pygdb.interact()


def test_trace():
	def hook_fopen(pygdb, bpType):
		if bpType == "OnEnter":
			rdi = pygdb.get_reg("rdi")
			filename = pygdb.readString(rdi)
			print("fopen:", filename)

	def hook_fread(pygdb, bpType):
		if bpType == "OnEnter":
			count = pygdb.get_reg("rsi")
			size = pygdb.get_reg("rdx")
			print("fread:", count*size)

	def hook_other_thread(pygdb, bpType):
		if bpType == "OnEnter":
			thread_num, addr_v = pygdb.get_thread_id()
			rdi = pygdb.get_reg("rdi")
			info = pygdb.readString(rdi)
			print("thread_%d(0x%x): printf(%s)"%(thread_num, addr_v, repr(info)))


	pygdb = PyGDB(target = "./test_thread")
	pygdb.hook("fopen", hook_fopen)
	pygdb.hook("fread", hook_fread)
	pygdb.hook(0x400C0A, hook_other_thread)

	pygdb.start()

	trace_handler = None

	b_addr = 0x400A88
	e_addr = 0x400B9C
	function_mode = True
	#function_mode = False
	show = True
	pygdb.trace(b_addr = b_addr, e_addr = e_addr, logPattern = "trace_log", byThread = True, asmCode = True, record_maps = [0x400000, 0x500000], trace_handler = trace_handler, function_mode = function_mode, show = show, oneThread = True)

	pygdb.interact()


def test_catch():
	def hook_syscall(pygdb, bpType, syscall_name):
		if bpType == "OnEnter":
			pc = pygdb.get_reg("pc")
			print(hex(pc), "enter", syscall_name)
			if syscall_name == "open":
				rdi = pygdb.get_reg("rdi")
				name = pygdb.readString(rdi)
				print("open", name)
			elif syscall_name == "read":
				rdx = pygdb.get_reg("rdx")
				print("read size", hex(rdx))
		elif bpType == "OnRet":
			pc = pygdb.get_reg("pc")
			print(hex(pc), "return", syscall_name)

	def hook_image(pygdb, libname, t_type):
		print("-"*0x20)
		print(t_type, libname)

	def hook_signal(pygdb, info):
		print("-"*0x20)
		print("signal", info)

	pygdb = PyGDB(target = "./test_hook")
	pygdb.hook_catch_syscall("open", hook_syscall, ["open"])
	addr_v = pygdb.hook_catch_syscall("read", hook_syscall, ["read"])

	pygdb.hook_catch_load("", hook_image, ["load"])
	pygdb.hook_catch_unload("", hook_image, ["unload"])

	pygdb.hook_catch_signal("all", hook_signal, [])

	pygdb.start()
	pygdb.globals["cmp_count"] = 0

	pygdb.run_until(0x400562)
	pygdb.remove_hook(addr_v)
	print(pygdb.hook_map.keys())

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
	gen_from_syscall(int write(int fd, char* data, int size));
	gen_from_syscall(int open(char* filename, int mode, int flag));
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

import socket
def test_inject():
	pygdb = PyGDB(target = "./test_hook")
	#pygdb.
	bp_id, bp_addr = pygdb.set_bp("main")
	#pygdb.interact()
	pygdb.start()
	pygdb.del_bp(bp_id)

	context(arch = pygdb.arch, os = 'linux')
		
		
	close_code = pygdb.gen_inject_asm(shellcraft.close("rdi"))
	recv_data = pygdb.gen_stack_value("recv_data", "welcome to test\x00")
	socket_data = pygdb.gen_stack_value("socket_addr", p16(2) + p16(0x4444) + p32(0x0100007f) + p64(0))
	c_source = """
	int strlen_diy(char *data);
	void close_diy(int fd);
	gen_from_syscall(int write(int fd, char* data, int size));
	gen_from_syscall(int read(int fd, char* data, int size));
	gen_from_syscall(int socket(int af, int sock, int flag));
	gen_from_syscall(int bind(int fd, char *addr, int size));
	gen_from_syscall(int listen(int fd, int size));
	gen_from_syscall(int accept(int fd, char *addr, char *flag));
	gen_from_syscall(int close(int fd));
	gen_from_syscall(int setsockopt(int fd, int level, int optname, char* optval, int optlen));
	gen_from_embed(memset);
	gen_from_embed(strlen);
	gen_from_embed(mov_addr_rax);
	int main_logic_function(char *data, char val) {
		char recv_data[0x10] = {0};
		char socket_addr[0x10];
		%s
		int listen_fd = socket(2, 1, 0);
		int option = 1;
		mov_addr_rax(&option);
		gen_from_asm("mov r10, rax;");
		if (setsockopt(listen_fd, %d, %d, (char*)&option, sizeof(option)) < 0)
			return ;
		if (bind(listen_fd, socket_addr, 0x10) < 0)
			return ;
		if (listen(listen_fd, 0x10) < 0)
			return ;
		int conn_fd = accept(listen_fd, 0, 0);
		read(conn_fd, recv_data, 0x10);
		write(conn_fd, recv_data, 0x10);
		if (data)
			write(conn_fd, data, strlen(data));
		close(conn_fd);
		return ;
	}
	int print(void *data) {
		return write(1, data, strlen(data));
	}
	"""%(socket_data, socket.SOL_SOCKET, socket.SO_REUSEADDR)

	data = pygdb.gen_from_pwntools("gen_from_pwntools(listen(0x4444));", show = True)
	data = pygdb.gen_from_pwntools("gen_from_pwntools(setsockopt(0x3, 1, 1));", show = True)
	data = pygdb.gen_from_syscall("gen_from_syscall(int listen(int fd, int size));")
	print("data:")
	print(data)

	code_data = pygdb.gen_payload(c_source, "main_logic_function")#, obj_name = "uuu_obj")
	code_addr = 0x8304000
	data_addr = 0x8300000
	#print data.encode("hex")

	map_config = {
		data_addr:[0x1000, "rw"],
		code_addr:[0x2000, "wx"],
	}
	data_config = {
		data_addr:"welcome to use PyGDB\n", 
		code_addr:code_data, 
	}

	pygdb.init_map_config(map_config)
	pygdb.init_data_config(data_config)

	args = [data_addr, 0x20]
	pygdb.call(code_addr, args)

	#code_data = pygdb.gen_payload(c_source, "main_logic_function")#, obj_name = "uuu_obj")
	#pygdb.make_tiny_elf(code_data, 'code.bin', 0x600000)
	"""
	pygdb.set_reg("rdi", data_addr)
	pygdb.set_reg("rsi", 0x20)
	pygdb.set_reg("pc", code_addr)

	#pygdb.run_until(0x83040bc)
	#"""
	pygdb.interact()
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
		print "\t python test_pygdb.py intel/arm/hook/mmap/patch/dup_io/trace/catch/inject/inject_hook"
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
		elif sys.argv[1] == "trace":
			test_trace()
		elif sys.argv[1] == "catch":
			test_catch()
		elif sys.argv[1] == "inject":
			test_inject()
		elif sys.argv[1] == "inject_hook":
			test_inject_hook()
