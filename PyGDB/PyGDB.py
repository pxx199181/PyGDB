
try:
	from pwn import *
	from pwnlib.util import misc
	which = misc.which

	io_wrapper = "pwntools"
except:
	from zio import *
	from zio import which
	u8 = p8 = l8
	u16 = p16 = l16
	u32 = p32 = l32
	u64 = p64 = l64

	io_wrapper = "zio"

import os
import json
import re
import threading
import string
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

import commands
def do_command(cmd_line):
	(status, output) = commands.getstatusoutput(cmd_line)
	return output

def split_multi(data, spec):
	items = []
	for item in data.split(spec):
		if len(item) == 0:
			continue
		items.append(item)
	return items

def encode_unicode(data):
	return "".join(chr(ord(c)&0xff) for c in data)

def byteify(input, encoding='utf-8'):
	if isinstance(input, dict):
		return {byteify(key): byteify(value) for key, value in input.iteritems()}
	elif isinstance(input, list):
		return [byteify(element) for element in input]
	elif isinstance(input, unicode):
		#return input.encode(encoding)
		return encode_unicode(input)
	else:
		return input


alpha_bet_printable = string.printable[:-5]
def PyGDB_hexdump(data, addr = 0, show = True, width = 16):
	ascii_info = ""
	line_info = ""
	all_info = ""
	half_width = width / 2

	for i in range(len(data)):
		if i % width == 0:
			all_info += "0x%08x: "%(i + addr)

		line_info += "%02x "%ord(data[i])

		if i%half_width == half_width-1:
			line_info += " "

		if data[i] in alpha_bet_printable:
			ascii_info += data[i]
		else:
			ascii_info += "."

		if i % width == width - 1:
			all_info += line_info + ascii_info + "\n"
			ascii_info = ""
			line_info = ""

	if ascii_info != "":
		all_info += line_info.ljust(3*width + 2, ' ') + ascii_info
		ascii_info = ""
		line_info = ""
	else:
		all_info = all_info[:-1]

	if show:
		print all_info
	return all_info


def PyGDB_unhexdump(data, width = 16):
	final_data = ""
	for line in data.split("\n"):
		if ": " in line:
			line = line[line.index(": ") + 2:]
		line = line.strip()

		#print "line:", line, len(line), width*3
		if len(line) == 0:
			continue

		line = line[:width*3+1]
		final_data += line.replace(" ", "").decode("hex")

	return final_data

class PyGDB():
	def __init__(self, target_path = None, arch = None):
		PYGDBFILE = os.path.abspath(os.path.expanduser(__file__))
		#print("PYGDBFILE:", PYGDBFILE)
		while os.path.islink(PYGDBFILE):
			PYGDBFILE = os.path.abspath(os.path.join(os.path.dirname(PYGDBFILE), os.path.expanduser(os.readlink(PYGDBFILE))))
		peda_dir = os.path.join(os.path.dirname(PYGDBFILE), "peda-arm")
		#print("peda_dir:", peda_dir)

		if target_path is not None:
			while os.path.islink(target_path):
				target_path = os.path.abspath(os.path.join(os.path.dirname(target_path), os.path.expanduser(os.readlink(target_path))))
		
		self.globals = {}
		self.arch = arch
		self.hook_map = {}
		self.io = None
		self.gdb_pid = None
		self.dbg_pid = None

		self.is_local = False
		self.code_base = None
		self.libc_base = None
		self.heap_base = None

		#self.gdb_path = misc.which('gdb-multiarch') or misc.which('gdb')
		self.gdb_path = which('gdb-multiarch') or which('gdb')
		if not self.gdb_path:
			print("'GDB is not installed\n$ apt-get install gdb'")
			exit(0)

		self.bin_path = None
		if target_path is not None:
			self.bin_path = target_path

			if (self.arch == None):
				self.arch = self.getarch()

		if self.arch is None:
			self.arch = "i386"

		self.arch_args = []
		if self.arch.lower() in ["arch64", "arm"]:
			self.peda_file = os.path.join(peda_dir, "peda-arm.py")
			
			for i in range(13):
				self.arch_args.append("r%d"%i)
		else:
			self.peda_file = os.path.join(peda_dir, "peda-intel.py")
			if "64" in self.arch:
				self.arch_args = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

		self.gdb_argv = []
		self.gdb_argv.append(self.gdb_path)
		self.gdb_argv.append("-q")
		self.gdb_argv.append("-nh")
		self.gdb_argv.append("-ex")
		self.gdb_argv.append("source %s"%(self.peda_file))

		#self.banner = do_command(" ".join(self.gdb_argv) + " --batch")
		#print(self.banner)
		self.run_gdb()

		if self.bin_path is not None:
			self.do_gdb("file %s"%self.bin_path)


	def getarch(self):
		capsize = 0
		word = 0
		arch = 0
		data = do_command("file %s"%self.bin_path)
		tmp =  re.search(", (.*), ",data)
		if tmp :
			info = tmp.group()
			info = info[2:].split(" version")[0].lower()
			print("arch:", info)
			if "x86-64" in info:
				capsize = 8
				word = "gx "
				arch = "x86-64"
				return "amd64"
			elif "arch64" in info :
				capsize = 8
				word = "gx "
				arch = "arch64"
				return "arch64"
			elif "arm" in info :
				capsize = 4
				word = "wx "
				arch = "arm"
				return "arm"
			elif "80386" in info:
				word = "wx "
				capsize = 4
				arch = "i386"
				return  "i386"
			else:
				return None
		else :
			return None

	def run_gdb(self):
		if io_wrapper == "zio":
			self.io = zio(self.gdb_argv, print_read = False, print_write = False)
			pids = [self.io.pid, 0]
		else:
			self.io = process(argv = self.gdb_argv)
			pids = proc.pidof(self.io)

		
		print("gdb pid", pids)
		self.gdb_pid = pids[0]

	def init_gdb(self):
		self.run_gdb()
		#self.do_gdb("set non-stop on")

	def attach(self, target):
		self.is_local = False
		if type(target) == str:
			self.do_gdb_ret("target remote %s"%target)
		else:
			print("attach %d"%target)
			print(self.do_gdb_ret("attach %d"%target))

	def start(self):
		self.is_local = True
		result = self.do_gdb_ret("start")
		self.dbg_pid = self.get_dbg_pid()

	def run(self):
		self.is_local = True
		result = self.do_gdb_ret("run")
		self.dbg_pid = self.get_dbg_pid()
			 
	def do_pygdb_ret(self, cmdline):
		self.io.sendline("pyCmdRet %s"%cmdline)

		begin_s = "pyCmd-B{"
		end_s = "}pyCmd-E"
		self.io.recvuntil(begin_s)
		#data = self.io.recvuntil("}pyCmd-E", drop = True)
		data = self.io.recvuntil(end_s)
		data = data[:-len(end_s)]
		data = data.decode("hex")
		if data == '':
			return ''
		value = json.loads(data)
		value = value["data"]
		value = byteify(value)
		return value

	def do_pygdb(self, cmdline):
		self.io.sendline("pyCmd %s"%cmdline)

	def do_gdb_ret(self, cmdline):
		return self.do_pygdb_ret("gdb_cmd " + cmdline)

	def do_gdb(self, cmdline):
		return self.do_pygdb("gdb_cmd " + cmdline)

	def get_regs(self):
		return self.do_pygdb_ret("get_regs")

	def get_reg(self, reg):
		return self.do_pygdb_ret("get_reg %s"%reg)

	def set_reg(self, reg, value):
		return self.do_pygdb_ret("set_reg %s 0x%x"%(reg, value))

	def cut_str(self, data, prefix = None, suffix = None):
		if prefix is not None:
			b_pos = data.find(prefix)
			if b_pos == -1:
				return None
			b_pos += len(prefix)
		else:
			b_pos = 0

		if suffix is not None:
			e_pos = data.find(suffix, b_pos)
			if e_pos == -1:
				return None
		else:
			e_pos = len(data)
		return data[b_pos:e_pos]


	def set_bp(self, addr, temp = False, hard = False, is_pie = False):
		cmdline = ""
		if temp:
			cmdline = "temp"
		elif hard: 
			cmdline = "hard"

		addr = self.real_addr(addr, is_pie)
		if type(addr) is not str:
			addr_str = "0x%x"%addr
		else:
			addr_str = addr

		ret_v = self.do_pygdb_ret("set_breakpoint %s %s"%(addr_str, cmdline))
		#print ret_v
		b_num = re.search("reakpoint \d+ at", ret_v)
		if b_num :
			b_num = b_num.group().split()[1]
			fini_num = int(b_num)

			addr_v = self.cut_str(ret_v, " %d at "%fini_num)
			if ": " in addr_v:
				addr_v = addr_v.split(": ")[0]
			if addr_v is not None:
				addr_v = int(addr_v, 16)

			return fini_num, addr_v
		return None, None

	def del_bp(self, num = None):
		cmdline = ""
		if num is not None:
			cmdline = "%d"%num
		return self.do_pygdb_ret("del_breakpoint %s"%(cmdline))

	def get_bp(self, num = None):
		cmdline = ""
		if num is not None:
			cmdline = "%d"%num
		return self.do_pygdb_ret("get_breakpoint %s"%(cmdline))

	def get_code(self, pc = None, count = None):
		cmdline = ""
		if pc is not None:
			cmdline += " %d"%pc
		if count is not None:
			cmdline += " %d"%count
		return self.do_pygdb_ret("get_code %s"%(cmdline))

	def get_stack(self, sp = None, count = None):
		cmdline = ""
		if sp is not None:
			cmdline += " %d"%sp
		if count is not None:
			cmdline += " %d"%count
		return self.do_pygdb_ret("get_stack %s"%(cmdline))

	def get_mem(self, addr, size):
		return self.do_pygdb_ret("read_mem 0x%x 0x%x"%(addr, size))

	def set_mem(self, addr, data):
		return self.do_pygdb_ret("write_mem 0x%x 0x%s"%(addr, data[::-1].encode("hex")))

	def stepi(self, count = None):
		cmdline = ""
		if count is not None:
			cmdline = "%d"%count
		return self.do_pygdb_ret("stepi %s"%(cmdline))

	def stepo(self, count = None):
		cmdline = ""
		if count is not None:
			cmdline = "%d"%count
		return self.do_pygdb_ret("stepover %s"%(cmdline))

	def _continue(self):
		return self.do_pygdb_ret("continue")

	def get_dbg_pid(self):
		return self.do_pygdb_ret("get_dbg_pid")

	def interrupt_process(self):
		if self.is_local == False:
			#print("kill -2 %d"%self.gdb_pid)
			os.system("kill -2 %d"%self.gdb_pid)
			#os.kill(self.gdb_pid, 2)
		else:
			#print("kill -2 %s"%self.dbg_pid)
			os.system("kill -2 %s"%self.dbg_pid)

	def _hexdump(self, addr, count):
		return self.do_pygdb_ret("hexdump 0x%x 0x%x"%(addr, count))

	def kill(self):
		self.do_gdb("k")

	def detach(self):
		self.do_gdb("detach")

	def quit(self):
		if self.is_local == True:
			self.kill()
		else:
			self.detach()

	def interact(self):
		self.do_pygdb("set_interact_mode 1")
		print('[+] ' + 'Switching to interactive mode')
		self.io.sendline("context")

		if io_wrapper == "zio":
			self.io.interact()
			return ;

		go = threading.Event()
		def recv_thread():
			while not go.isSet():
				try:
					cur = self.io.recv(timeout = 0.05)
					#cur = self.io.read_until_timeout(timeout = 0.05)
					cur = cur.replace('\r\n', '\n')
					if cur:
						sys.stdout.write(cur)
						sys.stdout.flush()
				except EOFError:
					print('[+] ' + 'Got EOF while reading in interactive')
					break
				except KeyboardInterrupt:
					pass
			print "over"

		#t = context.Thread(target = recv_thread)
		t = threading.Thread(target = recv_thread)
		t.daemon = True
		t.start()

		import time
		time.sleep(0.5)


		is_running = True
		prompt = ""#term.text.bold_red("gdb-peda $")

		while is_running:
			try:
				while not go.isSet():
					#if False:#term.term_mode:
					#	data = term.readline.readline(prompt = prompt, float = True)
					#else:
					#	data = sys.stdin.read(1)

					data = raw_input(" "*len("gdb-peda $"))
					try:
						self.io.send(data)
					except EOFError:
						go.set()
						print('[+] ' + 'Got EOF while sending in interactive')
					
					if data.strip() in ["q", "quit"]:
						self.quit()
						is_running = False
						go.set()
						break
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				self.interrupt_process()
		while t.is_alive():
			t.join(timeout = 0.1)

	def procmap(self):
		if self.dbg_pid is None:
			self.dbg_pid = self.get_dbg_pid()
			if self.dbg_pid is None:
				data = self.do_gdb_ret("info proc exe")
				pid = re.search("process.*", data)
				if pid :
					pid = pid.group().split()[1]
					self.dbg_pid = int(pid)
				else :
					return "error"

		with open("/proc/{}/maps".format(self.dbg_pid), "r") as maps:
			return maps.read()

	def libcbase(self):
		data = re.search(".*libc.*\.so", self.procmap())
		if data :
			libcaddr = data.group().split("-")[0]
			self.libc_base = int(libcaddr, 16)
			self.do_gdb("set $libc={}".format(hex(int(libcaddr, 16))))
			return int(libcaddr, 16)
		else :
			self.libc_base = None
			return 0

	def codeaddr(self): # ret (start, end)
		pat = ".*"
		data = re.findall(pat, self.procmap())
		if data :
			codebaseaddr = data[0].split("-")[0]
			self.code_base = int(codebaseaddr, 16)
			codeend = data[0].split("-")[1].split()[0]
			self.do_gdb("set $code={}".format(hex(int(codebaseaddr, 16))))
			return (int(codebaseaddr, 16), int(codeend, 16))
		else :
			self.code_base = None
			return (0, 0)

	def getheapbase(self):
		data = re.search(".*heap\]", self.procmap())
		if data :
			heapbase = data.group().split("-")[0]
			self.heap_base = int(heapbase, 16)
			self.do_gdb("set $heap={}".format(hex(int(heapbase, 16))))
			return int(heapbase, 16)
		else :
			self.heap_base = None
			return 0

	def get_codebase(self):
		if self.code_base is None:
			self.code_base = self.codebase()
		return self.code_base

	def codebase(self):
		return self.codeaddr()[0]

	def heap(self):
		return self.getheapbase()

	def libc(self):
		return self.libcbase()

	def attach_name(self, binary_name, idx = 0):
		b_pos = binary_name.rfind("/")
		if b_pos != -1:
			exe_name = binary_name[b_pos + 1:]
		else:
			exe_name = binary_name
		data = do_command("pidof %s"%exe_name).split(" ")[idx]
		pid = int(data)
		self.attach(pid)
		return 

	def read_mem(self, addr, size):
		return self.get_mem(addr, size)

	def write_mem(self, addr, data):
		return self.set_mem(addr, data)

	def read_byte(self, addr):
		return u8(self.read_mem(addr, 1))

	def read_word(self, addr):
		return u16(self.read_mem(addr, 2))

	def read_int(self, addr):
		return u32(self.read_mem(addr, 4))

	def read_long(self, addr):
		return u64(self.read_mem(addr, 8))

	def write_byte(self, addr, value):
		self.write_mem(addr, p8(value))

	def write_word(self, addr, value):
		self.write_mem(addr, p16(value))
	
	def write_int(self, addr, value):
		self.write_mem(addr, p32(value))
	
	def write_long(self, addr, value):
		self.write_mem(addr, p64(value))

	def _read_mid_list(self, addr, count, bc = 4):
		f_i = {}
		f_i[1] = u8
		f_i[2] = u16
		f_i[4] = u32
		f_i[8] = u64

		u_f = f_i[bc]

		data = self.read_mem(addr, count*bc)
		#print len(data)
		#print data.encode("hex")
		result = map(u_f, [data[i*bc:(i+1)*bc] for i in range(len(data)/bc)])
		return result

	def read_byte_list(self, addr, count):
		return self._read_mid_list(addr, count, 1)

	def read_word_list(self, addr, count):
		return self._read_mid_list(addr, count, 2)

	def read_int_list(self, addr, count):
		return self._read_mid_list(addr, count, 4)

	def read_long_list(self, addr, count):
		return self._read_mid_list(addr, count, 8)

	def _write_mid_list(self, addr, data_list, bc = 4):
		f_i = {}
		f_i[1] = p8
		f_i[2] = p16
		f_i[4] = p32
		f_i[8] = p64
		u_f = f_i[bc]
		result = map(u_f, data_list)
		self.write_mem(addr, "".join(result))
		
	def write_byte_list(self, addr, data_list):
		return self._write_mid_list(addr, data_list, 1)

	def write_word_list(self, addr, data_list):
		return self._write_mid_list(addr, data_list, 2)

	def write_int_list(self, addr, data_list):
		return self._write_mid_list(addr, data_list, 4)

	def write_long_list(self, addr, data_list):
		return self._write_mid_list(addr, data_list, 8)

	def real_addr(self, addr, is_pie = False):
		if type(addr) is not str:
			if is_pie == True:
				addr += self.get_codebase()
		return addr

	def hook(self, addr, handler, args, is_pie = False):
		addr = self.real_addr(addr, is_pie)

		if addr in self.hook_map.keys():
			self.remove_hook(addr)

		num, addr_v = self.set_bp(addr)
		self.hook_map[addr_v] = [num, handler, args, addr]
		return 

	def clear_hook(self):
		for addr in self.hook_map.keys():
			self.remove_hook(addr)
		self.hook_map = {}

	def remove_hook(self, addr, is_pie = False):
		addr = self.real_addr(addr, is_pie)

		if addr in self.hook_map.keys():
			num = self.hook_map[addr][0]
			self.del_bp(num)
			self.hook_map.pop(addr)
		elif type(addr) is str:
			for key in self.hook_map.keys():
				if addr == self.hook_map[key][3]:
					num = self.hook_map[key][0]
					self.del_bp(num)
					self.hook_map.pop(key)
					break

	def run_until(self, addr, is_pie = False):
		addr = self.real_addr(addr, is_pie)

		num, addr_v = self.set_bp(addr)
		bps = self.get_bp()

		#print "num", num, "addr_v", addr_v
		while True:
			pc = self.Continue()
			if pc == -1:
				break

			if pc == addr_v:
				self.del_bp(num)
				break

	def Continue(self):
		while True:
			try:
				self._continue()
				pc = self.get_reg("pc")
				if pc in self.hook_map.keys():
					num, handler, args, addr = self.hook_map[pc]
					ret_v = handler(*args)
					if ret_v is not None and ret_v == False:
						return pc
				else:
					return pc
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				self.interrupt_process()
				return -1

	def hexdump(self, addr = 0, size = 0x10, show = True, width = 16, data = None):
		if data is not None:
			return PyGDB_hexdump(data, addr, show, width)
		else:
			data = self.read_mem(addr, size)
			return PyGDB_hexdump(data, addr, show, width)

	def unhexdump(self, data, width = 16):
		return PyGDB_unhexdump(data, width)


	def readString(self, addr):
		final_data = ""
		while True:
			data = self.read_mem(addr+len(final_data), 0x100)
			pos = data.find("\x00")
			if pos != -1:
				final_data += data[:pos]
				break
			if data is None or data == "":
				break
			final_data += data

		return final_data

	def mmap(self, addr, size = 0x1000, prot_value = 7):
		if io_wrapper == "zio":
			print("please install pwntools")
			return

		if self.arch == "x86-64":
			self.arch = "amd64"
		context(arch = self.arch, os = 'linux')

		if (addr & 0xfff) != 0:
			size = size + 0x1000 - (addr&0xfff)
		if (size & 0xfff) != 0:
			size = ((size/0x1000) + 1)*0x1000

		prot = self.prot_eval(prot_value)

		shellcode_asm = shellcraft.mmap(addr, size, prot, 0x22, -1, 0)
		shellcode = asm(shellcode_asm)

		pc = self.get_reg("pc")
		old_data = self.read_mem(pc, len(shellcode))
		self.write_mem(pc, shellcode)

		self.run_until(pc + len(shellcode))
		self.write_mem(pc, old_data)
		self.set_reg("pc", pc)

	def prot_eval(self, prot_value):

		if type(prot_value) != str:
			return prot_value

		flag = 0
		if "r" in prot_value:
			flag |= 0x1
		if "w" in prot_value:
			flag |= 0x2
		if "x" in prot_value:
			flag |= 0x4
		return flag

	def init_map_config(self, map_config):
		"""
		map_config = {
			va: [size, "rwx"]
		}
		"""
		for addr in map_config.keys():
			value = map_config[addr]
			size = value[0]
			flag = value[1]
			self.mmap(addr, size, flag)

	def readfile(self, filename, mode = "rb"):
		with open(filename, mode) as fd:
			return fd.read()

	def writefile(self, filename, data, mode = "wb"):
		with open(filename, mode) as fd:
			return fd.write(data)

	def init_data_config(self, data_config):
		"""
		data_config = {
			va: data
			va: [data]
			va: [filename, offset, size]
		}
		"""
		for addr in data_config.keys():
			value = data_config[addr]
			if type(value) == str:
				data = value
			elif len(value) == 1:
				data = value[0]
			elif len(value) == 3:
				filename = value[0]
				offset = value[1]
				size = value[2]
				data = self.readfile(filename)[offset:offset+size]
			self.write_mem(addr, data)

	def init_file_config(self, filename, file_config):
		"""
		filename
		file_config = {
			va: [offset, size]
		}
		"""
		data = self.readfile(filename)
		for addr in file_config.keys():
			value = file_config[addr]
			offset = value[0]
			size = value[1]
			self.write_mem(addr, data[offset:offset+size])

	def call(self, func_addr, args, use_addr = None):
		"""
		args = [arg0, arg1, arg2, ...]
		"""
		if io_wrapper == "zio":
			print("please install pwntools")
			return 

		pc = self.get_reg("pc")
		sp = self.get_reg("sp")
		old_data = ""
		if use_addr is None:
			use_addr = pc
			old_data = self.read_mem(pc, 0x10)
		else:
			self.set_reg("pc", use_addr)

		asm_info = ""
		asm_info += "call 0x%x\n"%func_addr
		asm_info += "nop"

		data = asm(asm_info ,vma = use_addr, arch = self.arch, os = "linux")
		#print data
		disasm_info = disasm(data, vma = use_addr, arch = self.arch, os = "linux")
		#print disasm_info
		addr_hex = disasm_info.strip().split("\n")[1].split(":")[0].strip()
		next_addr = int(addr_hex, 16)
		
		#sp = self.get_reg("sp")
		self.write_mem(use_addr, data)

		repair_stack_offset = 0


		if self.arch.lower() in ["arm", "arch64"]:
			for i in range(len(args)):
				self.set_reg("r%d"%i, args[i])
		else:
			if "64" in self.arch:
				reg_names = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

				less_count = 6 if (len(args) > 6) else len(args)

				for i in range(less_count):
					self.set_reg(reg_names[i], args[i])

				if len(args) > 6:
					for i in range(len(args)-6):
						self.write(sp - i*8, args[i+6])

					self.set_reg("sp", sp-(len(args)-6)*8)
			else:
				for i  in range(len(args)):
					for i in range(len(args)):
						self.write(sp - i*4, args[i])

					self.set_reg("sp", sp-len(args)*4)

		if len(self.hook_map.keys()) != 0:
			self.run_until(next_addr)
		else:
			self.stepo()

		cur_pc = self.get_reg("pc")
		if cur_pc != next_addr:
			self.interact()

		#self.del_bp(bp_num)
		self.set_reg("pc", pc)
		self.set_reg("sp", sp)
		if old_data != "":
			self.write_mem(pc, old_data)

		ret_v = 0
		if self.arch.lower() in ["arm", "arch64"]:
			ret_v = self.get_reg("r0")
		else:
			if "64" in self.arch:
				ret_v = self.get_reg("rax")
			else:
				ret_v = self.get_reg("eax")

		return ret_v

	def run_cmd(self, cmd_line):
		import commands
		(status, data) = commands.getstatusoutput(cmd_line)
		return data

	def gen_rand_str(self, size = 16):
		import string
		import random
		data = ""
		alpha_bet = string.ascii_letters  + string.digits + "_"
		while len(data) < size:
			idx = random.randint(0, len(alpha_bet) - 1)
			data += alpha_bet[idx]

		return data


	def gen_payload(self, source_data, entry_name, gcc_path = "gcc", option = "", obj_name = None):
		
		if io_wrapper == "zio":
			print("please install pwntools")
			return 

		option += " -fno-stack-protector"
		if self.arch.lower() not in ["arm", "arch64"]:
			if "64" not in self.arch:
				option += " -m32"

		source_data = self.gen_from_pwntools(source_data)

		c_model = ""
		c_model += source_data + "\n"
		c_model += "int main() {\n"
		c_model += "}"

		auto_gen = False
		if obj_name is None:
			obj_name = "/tmp/%s"%self.gen_rand_str()
			auto_gen = True
		
		cfile_name = obj_name + ".c"
		#print c_model
		self.writefile(cfile_name, c_model)
		cmdline = "%s -o %s %s %s"%(gcc_path, obj_name, cfile_name, option)
		res = self.run_cmd(cmdline)
		if ("error: " not in res.lower()):
			elf_info = ELF(obj_name)

			entry_addr = elf_info.symbols[entry_name]
			main_addr = elf_info.symbols["main"]

			size = main_addr - entry_addr
			data = elf_info.read(entry_addr, size)
		else:
			print res
			data = "error"

		if auto_gen:
			import os
			os.unlink(cfile_name)
			os.unlink(obj_name)

		return data

	def gen_inject_asm(self, code_asm):
		if io_wrapper == "zio":
			print("please install pwntools")
			return

		if self.arch == "x86-64":
			self.arch = "amd64"
		context(arch = self.arch, os = 'linux')
		
		code_data = asm(code_asm, arch = self.arch, os = "linux")
		content = ""
		content += "__asm__ __volatile__(\""
		content += "".join([".byte 0x%x;"%ord(c) for c in code_data])
		content += "\"::);"
		return content

	def gen_stack_value(self, name, value = ""):
		#print "char %s[%d];"%(n_s, len(name))
		content = ""
		for i in range(len(value)/4):
			content += "*(unsigned int*)(&%s[0x%x]) = 0x%x;\n"%(name, i*4, u32(value[i*4:i*4+4]))

		cur_pos = (len(value)/4)*4
		if len(value) - cur_pos >= 2:
			content += "*(unsigned short int*)(&%s[0x%x]) = 0x%x;\n"%(name, cur_pos, u16(value[cur_pos:cur_pos+2]))
			cur_pos += 2
		if len(value) - cur_pos >= 1:
			content += "*(unsigned char*)(&%s[0x%x]) = 0x%x;\n"%(name, cur_pos, u8(value[cur_pos:cur_pos+2]))
			cur_pos += 1

		return content

	def patch_file(self, infile, patch_config, outfile = None):
		"""
		patch_config:
		{
			offset: data
		}
		"""
		def patch_data(data, offset, content):
			return data[:offset] + content + data[offset + len(content):]

		data = self.readfile(infile)
		for offset in patch_config:
			data = patch_data(data, offset, patch_config[offset])
		self.writefile(outfile, data)


	def gen_from_pwntools(self, c_source):
		name_map = {}
		start_model = "gen_from_pwntools("

		prefix_list = []
		suffix_list = []
		mid_list = []
		for line in c_source.split("\n"):
			line_new = line.strip()
			if line_new.startswith(start_model):
				pos_e = line_new.rfind(")")
				if pos_e == -1:
					continue
				voto_info = line_new[len(start_model):pos_e].replace("\t", " ")
				while voto_info.find("  ") != -1:
					voto_info = line_new.replace("  ", " ")
				name = voto_info.split(" ")[1].split("(")[0]
				
				args_count = len(voto_info.split(","))
				code_asm = ""
				if args_count > 1:
					if "i386" in self.arch.lower():
						#code_asm = getattr(shellcraft, name)(self.arch_args[:args_count])
						args_name = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp"]
						in_arg_list = []
						for i in range(args_count):
							code_asm += "push %s\n"%args_name[i]
							in_arg_list.append(args_name[i])
						code_asm += getattr(shellcraft, name)(*(args_name[:args_count]))
						for i in range(args_count-1, -1, -1):
							code_asm += "pop %s\n"%args_name[i]
							in_arg_list.append(args_name[i])
					else:
						print getattr(shellcraft, name)("rdi", "rsi")
						print shellcraft.write(*(self.arch_args[:args_count]))
						print getattr(shellcraft, name)(*(self.arch_args[:args_count]))
						code_asm = getattr(shellcraft, name)(*(self.arch_args[:args_count]))
				else:
					code_asm = getattr(shellcraft, name)()

				inject_asm = self.gen_inject_asm(code_asm)
				
				prefix_list.append(voto_info + ";")

				define_content = ""
				define_content += voto_info + "{\n"
				define_content += inject_asm + "\n"
				define_content += "}"

				suffix_list.append(define_content)

			else:
				mid_list.append(line)
		new_content = ""
		new_content += "\n".join(prefix_list + mid_list + suffix_list)

		return new_content

