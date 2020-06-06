import mf_angelheap
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


def to_int(val):
	"""
	Convert a string to int number
	from https://github.com/longld/peda
	"""
	try:
		return int(str(val), 0)
	except:
		return None

def normalize_argv(args, size=0):
	"""
	Normalize argv to list with predefined length
	from https://github.com/longld/peda
	"""
	args = list(args)
	for (idx, val) in enumerate(args):
		if to_int(val) is not None:
			args[idx] = to_int(val)
		if size and idx == size:
			return args[:idx]

	if size == 0:
		return args
	for i in range(len(args), size):
		args += [None]
	return args

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
	def __init__(self, target = None, arch = None):
		self.load_init(target, arch)
		mf_angelheap.init_gdb(self)

	def load_init(self, target = None, arch = None):
		PYGDBFILE = os.path.abspath(os.path.expanduser(__file__))
		#print("PYGDBFILE:", PYGDBFILE)
		while os.path.islink(PYGDBFILE):
			PYGDBFILE = os.path.abspath(os.path.join(os.path.dirname(PYGDBFILE), os.path.expanduser(os.readlink(PYGDBFILE))))
		peda_dir = os.path.join(os.path.dirname(PYGDBFILE), "peda-arm")
		#print("peda_dir:", peda_dir)

		if target is not None:
			while os.path.islink(target):
				target = os.path.abspath(os.path.join(os.path.dirname(target), os.path.expanduser(os.readlink(target))))
		
		self.globals = {}
		self.priv_globals = {}
		self.arch = arch
		self.hook_map = {}
		self.io = None
		self.gdb_pid = None
		self.dbg_pid = None

		self.is_local = False
		self.code_base = None
		self.libc_base = None
		self.heap_base = None

		self.target_argv = ""

		#self.gdb_path = misc.which('gdb-multiarch') or misc.which('gdb')
		self.gdb_path = which('gdb-multiarch') or which('gdb')
		if not self.gdb_path:
			print("'GDB is not installed\n$ apt-get install gdb'")
			exit(0)

		self.bin_path = None
		if target is not None:
			self.bin_path = target

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
			self.do_gdb("file")
			self.do_gdb_ret("target remote %s"%target)
			self.target_argv = "target remote %s"%target
		else:
			self.do_gdb("file")
			print("attach %d"%target)
			print(self.do_gdb_ret("attach %d"%target))
			self.target_argv = "attach %d"%target

	def start(self):
		self.is_local = True
		result = self.do_gdb_ret("start")
		self.dbg_pid = self.get_dbg_pid()
		self.target_argv = "attach %d"%self.dbg_pid

	def run(self):
		self.is_local = True
		result = self.do_gdb_ret("run")
		self.dbg_pid = self.get_dbg_pid()
		self.target_argv = "attach %d"%self.dbg_pid
			 
	def do_pygdb_ret(self, cmdline):
		self.io.sendline("pyCmdRet %s"%cmdline)

		begin_s = "pyCmd-B{"
		end_s = "}pyCmd-E"
		#self.io.recvuntil(begin_s)
		#data = self.io.recvuntil("}pyCmd-E", drop = True)
		while True:
			data = self.io.recvuntil(end_s)
			pos = data.rfind(begin_s)
			if pos != -1:
				#print "data:", data
				data = data[pos + len(begin_s):-len(end_s)]
				break
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

	def interact(self, prompt = "~> "):
		self.do_pygdb("set_interact_mode 1")
		print('[+] ' + 'Switching to interactive mode')
		self.io.sendline("source ~/.gdbinit")

		prompt = term.text.bold_red(prompt)
		self.io.sendline("set prompt %s" % (prompt))

		self.io.recvuntil(prompt)
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

		t = threading.Thread(target = recv_thread)
		t.daemon = True
		t.start()

		import time
		time.sleep(0.5)

		is_running = True
		while is_running:
			try:
				while not go.isSet():
					#data_all = raw_input(" "*len(prompt))
					data_all = ""
					while True:
						data = sys.stdin.read(1)
						if data == '\x7f':
							sys.stdout.write("\r" + ' '*len(prompt + data_all))
							data_all = data_all[:-1]
							sys.stdout.write("\r" + prompt + data_all)
						else:
							data_all += data
							sys.stdout.write(data)						
						if data == '\n':
							break
					try:
						self.io.send(data_all)
					except EOFError:
						go.set()
						print('[+] ' + 'Got EOF while sending in interactive')
					
					if data_all.strip() in ["q", "quit"]:
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
		if self.code_base is not None:
			return self.code_base
		return self.codeaddr()[0]

	def heap(self):
		if self.heap_base is not None:
			return self.heap_base
		return self.getheapbase()

	def libc(self):
		if self.libc_base is not None:
			return self.libc_base
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

	def hook(self, addr, handler, args = [], hook_ret = None, is_pie = False):
		addr = self.real_addr(addr, is_pie)

		if addr in self.hook_map.keys():
			self.remove_hook(addr)

		num, addr_v = self.set_bp(addr)
		if hook_ret is not None:
			if hook_ret == True or hook_ret == 0:
				ret_addr = self.find_ret(addr)
			else:
				ret_addr = hook_ret
			num_ret, addr_v_ret = self.set_bp(ret_addr) 
			self.hook_map[ret_addr] = [num_ret, handler, args, ret_addr, ["OnRet", None, None]]
		else:
			num_ret, ret_addr = None, None
		self.hook_map[addr_v] = [num, handler, args, addr, ["OnEnter", num_ret, ret_addr]]
		return 
	
	def resore_hook(self):
		for addr in self.hook_map.keys():
			[num, handler, args, addr, hook_info] = self.hook_map[addr_v]
			num, addr_v = self.set_bp(addr)
			self.hook_map[addr_v] = [num, handler, args, addr, hook_info]
			return 

	def clear_hook(self):
		for addr in self.hook_map.keys():
			self.remove_hook(addr)
		self.hook_map = {}

	def remove_hook(self, addr, is_pie = False):
		addr = self.real_addr(addr, is_pie)

		if addr in self.hook_map.keys():
			num = self.hook_map[addr][0]
			hook_info = self.hook_map[addr][-1]
			if hook_info[1] is not None:
				self.del_bp(hook_info[1])
				self.hook_map.pop(hook_info[2])

			self.del_bp(num)
			self.hook_map.pop(addr)
					
		elif type(addr) is str:
			for key in self.hook_map.keys():
				if addr == self.hook_map[key][3]:
					num = self.hook_map[key][0]					
					hook_info = self.hook_map[key][-1]
					if hook_info[1] is not None:
						self.del_bp(hook_info[1])
						self.hook_map.pop(hook_info[2])

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
					num, handler, args, addr, hook_info = self.hook_map[pc]
					ret_v = handler(self, hook_info[0], *args)
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

	def call(self, func, args = [], lib_path = "libc.so.6", use_addr = None):
		"""
		args = [arg0, arg1, arg2, ...]
		"""
		if io_wrapper == "zio":
			print("please install pwntools")
			return 

		if type(func) == str:
			if lib_path is not None:
				func_addr = self.get_lib_symbol(func, lib_path)
			else:
				func_addr = self.get_symbol_value(func)
			#func_addr = self.get_lib_symbol(func, lib_path)
		else:
			func_addr = func

		pc = self.get_reg("pc")
		origin_sp = sp = self.get_reg("sp")

		args_new = []
		for item in args:
			if type(item) == str:
				sp -= len(item)
				args_new.append(sp)
				self.write_mem(sp, item)
			else:
				args_new.append(item)

		if "64" in self.arch:
			sp -= sp%8
		else:
			sp -= sp%4

		self.set_reg("sp", sp)
		args = args_new

		old_data = ""
		if use_addr is None:
			use_addr = pc
			old_data = self.read_mem(pc, 0x10)
		else:
			self.set_reg("pc", use_addr)


		if self.arch.lower() in ["arm", "arch64"]:
			call_reg = "r%d"%len(args)
			self.set_reg(call_reg, func_addr)
			asm_info = ""
			asm_info += "bl %s\n"%call_reg
			asm_info += "mov r0, r0"
		else:
			if "64" in self.arch:
				call_reg = "rax"
			else:
				call_reg = "eax"

			self.set_reg(call_reg, func_addr)
			asm_info = ""
			asm_info += "call %s\n"%call_reg
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

		#print [hex(c) for c in args]
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
						sp -= 8
						self.write_mem(sp, p64(args[-1-i]))

					self.set_reg("sp", sp)
			else:
				for i  in range(len(args)):
					sp -= 4
					self.write_mem(sp, p32(args[-1-i]))

				self.set_reg("sp", sp)

		#self.interact()
		if len(self.hook_map.keys()) != 0:
			self.run_until(next_addr)
		else:
			self.stepo()

		cur_pc = self.get_reg("pc")
		if cur_pc != next_addr:
			self.interact()

		#self.del_bp(bp_num)
		self.set_reg("pc", pc)
		self.set_reg("sp", origin_sp)
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

	def get_symbol_value(self, name):
		data = self.do_gdb_ret("print %s"%name)
		#print "data:", data
		pos_b = data.find(" 0x")
		if pos_b == -1:
			return 0
		value = data[pos_b+1:].split()[0]
		real_addr = int(value, 16)
		if real_addr == 0:
			print "[!]", name, ":", hex(real_addr)
		return real_addr

	def get_lib_symbol(self, name, lib_path = "libc.so.6"):
		self.save_context()
		if "dlopen" not in self.priv_globals.keys():
			if "__libc_dlopen_mode" not in self.priv_globals.keys():
				self.priv_globals["__libc_dlopen_mode"] = self.get_symbol_value("__libc_dlopen_mode")
				self.priv_globals["__libc_dlsym"] = self.get_symbol_value("__libc_dlsym")
			
			libdl = "libdl.so.2"
			args = [libdl + "\x00", 0x80000001]
			libdl_handle = self.call(self.priv_globals["__libc_dlopen_mode"], args)
			self.priv_globals["dlopen"] = self.get_symbol_value("dlopen")
			self.priv_globals["dlsym"] = self.get_symbol_value("dlsym")
			self.priv_globals["lib_handle"] = {}

		if lib_path not in self.priv_globals["lib_handle"].keys():
			args = [lib_path + "\x00", 1] #LAZY
			self.priv_globals["lib_handle"][lib_path] = self.call(self.priv_globals["dlopen"], args)
			#print "libc:", hex(self.priv_globals["lib_handle"])
		args = [self.priv_globals["lib_handle"][lib_path], name + "\x00"]
		real_addr = self.call(self.priv_globals["dlsym"], args)
		if real_addr == 0:
			print "[!]", name, ":", hex(real_addr)
		self.restore_context()
		return real_addr

	def fix_got(self, got_name, got_addr,  dlsym = True, lib_path = "libc.so.6"):
		if dlsym == True:
			real_addr = self.get_lib_symbol(got_name, lib_path)
		else:
			real_addr = self.get_symbol_value(got_name)
		#if real_addr == 0:
		#	print "[!]", got_name, ":", hex(real_addr)
		if "64" in self.arch:
			self.write_long(got_addr, real_addr)
		else:
			self.write_int(got_addr, real_addr)

	def fix_gots(self, got_list, lib_path = None):
		for items in got_list:
			if lib_path is not None:
				if len(items) == 2:
					items = items + [True, lib_path]
				elif len(items) == 3:
					if type(items[2]) == str:
						items = items[:-1] + [True, items[-1]]
					else:
						items = items + [lib_path]
			self.fix_got(*items)

	def save_context(self):
		self.priv_globals["regs"] = self.get_regs()

	def restore_context(self):
		#print self.globals["regs"]
		if "regs" not in self.priv_globals.keys():
			return
		regs = self.priv_globals["regs"]
		for reg_name in regs.keys():
			self.set_reg(reg_name, regs[reg_name])

	def run_in_new_terminal(self, command, terminal = None, args = None, sleep_time = 2):
		"""run_in_new_terminal(command, terminal = None) -> None

		Run a command in a new terminal.

		When ``terminal`` is not set:
			- If ``context.terminal`` is set it will be used.
			  If it is an iterable then ``context.terminal[1:]`` are default arguments.
			- If a ``pwntools-terminal`` command exists in ``$PATH``, it is used
			- If ``$TERM_PROGRAM`` is set, that is used.
			- If X11 is detected (by the presence of the ``$DISPLAY`` environment
			  variable), ``x-terminal-emulator`` is used.
			- If tmux is detected (by the presence of the ``$TMUX`` environment
			  variable), a new pane will be opened.
			- If GNU Screen is detected (by the presence of the ``$STY`` environment
			  variable), a new screen will be opened.

		Arguments:
			command (str): The command to run.
			terminal (str): Which terminal to use.
			args (list): Arguments to pass to the terminal

		Note:
			The command is opened with ``/dev/null`` for stdin, stdout, stderr.

		Returns:
		  PID of the new terminal process
		"""

		if not terminal:
			if 'TERM_PROGRAM' in os.environ:
				terminal = os.environ['TERM_PROGRAM']
				args	 = []
			elif 'DISPLAY' in os.environ and which('x-terminal-emulator'):
				terminal = 'x-terminal-emulator'
				args	 = ['-e']
			elif 'TMUX' in os.environ and which('tmux'):
				terminal = 'tmux'
				args	 = ['splitw']
			elif 'STY' in os.environ and which('screen'):
				terminal = 'screen'
				args	 = ['-t','pwntools-gdb','bash','-c']

		if isinstance(args, tuple):
			args = list(args)

		argv = [which(terminal)] + args

		if isinstance(command, str):
			if ';' in command:
				log.error("Cannot use commands with semicolon.  Create a script and invoke that directly.")
			argv += [command]
		elif isinstance(command, (list, tuple)):
			if any(';' in c for c in command):
				log.error("Cannot use commands with semicolon.  Create a script and invoke that directly.")
			argv += list(command)

		#log.debug("Launching a new terminal: %r" % argv)

		pid = os.fork()

		if pid == 0:
			# Closing the file descriptors makes everything fail under tmux on OSX.
			if platform.system() != 'Darwin':
				devnull = open(os.devnull, 'rwb')
				os.dup2(devnull.fileno(), 0)
				os.dup2(devnull.fileno(), 1)
				os.dup2(devnull.fileno(), 2)
			sleep(sleep_time)
			os.execv(argv[0], argv)
			os._exit(1)

		return pid

	def dup_io(self, port = 9999, ip = "0.0.0.0", new_terminal = True):
		self.save_context()
		"""
		struct sockaddr_in {
			 unsigned short		 sin_family;	
			 unsigned short int	 sin_port;	  
			 struct in_addr		 sin_addr;	  
			 unsigned char		  sin_zero[8];   
		};
		struct in_addr {
			unsigned long	 s_addr;
		};
		Lewis.sin_family	  = AF_INET;
		Lewis.sin_port		= htons(port);
		Lewis.sin_addr.s_addr = inet_addr(ip);
		memset(Lewis.sin_zero,0,sizeof(Lewis.sin_zero));
		"""
		def parse_ip(ip):
			data = ""
			for item in ip.split("."):
				data += p8(int(item))
			return data

		sockaddr_in = ""
		sockaddr_in += p16(2)
		sockaddr_in += p16(port, endian = 'big')
		sockaddr_in += parse_ip(ip)
		sockaddr_in += p64(0)

		#self.hexdump(data = sockaddr_in)
		#fd_tcp = socket(AF_INET, SOCK_STREAM, 0)
		server = self.call("socket", [2, 1, 0])
		#print "server", server

		# setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &flag, len) 
		SOL_SOCKET = 1
		SO_REUSEADDR = 2
		if self.call("setsockopt", [server, SOL_SOCKET, SO_REUSEADDR, p32(1), 4]) == -1:
			print "setsockopt error"
			return  
		#bind(server,(struct sockaddr *)&serv_addr,0x10)
		if (self.call("bind", [server, sockaddr_in, 0x10]) != 0):
			print "bind error"
			return 
		#print "bind", server
		#listen(server,0)
		self.call("listen", [server, 0])
		#print "listen", server

		if new_terminal:
			self.run_in_new_terminal("nc %s %d"%(ip, port), sleep_time = 0.5)
		else:
			print "wait io @ %s:%d"%(ip, port)
		
		#client=accept(server,0,0)
		client = self.call("accept", [server, 0, 0])
		#print "accept", client

		#dup2(client,0)
		#dup2(client,1)
		#dup2(client,2)
		self.call("dup2", [client, 0])
		self.call("dup2", [client, 1])
		self.call("dup2", [client, 2])

		self.restore_context()

	def patch_asm(self, addr, asm_info):
		data = self._asm_(asm_info, addr)
		self.write_mem(addr, data)

	def patch_config(self, patch_config):
		"""
		patch_config:
		{
			offset: data,
			offset: [data],
			offset: ["asm", data_asm],
			offset: ["data", data],
		}
		"""
		for addr in patch_config:
			#print addr
			value = patch_config[addr]
			data = ""
			if type(value) == str:
				data = value
				
			else:
				if len(value) == 1:
					data = value[0]
				elif value[0] == "data":
					data = value[1]
				elif value[0] == "asm":
					data = self._asm_(value[1], addr)
			self.write_mem(addr, data)

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

	def compile_cfile(self, source, gcc_path, option, infile, outfile):
		self.writefile(infile, source)
		cmdline = "%s %s -o %s %s"%(gcc_path, option, outfile, infile)
		res = self.run_cmd(cmdline)
		if ("error: " not in res.lower()):
			return True
		else:
			print res
			return False


	def gen_payload(self, source_data, entry_name, gcc_path = "gcc", option = "", obj_name = None):
		
		if io_wrapper == "zio":
			print("please install pwntools")
			return
		context(arch = self.arch, os = 'linux')

		if option == "":
			option += " -fno-stack-protector"

		if self.arch.lower() not in ["arm", "arch64"]:
			if "64" not in self.arch:
				option += " -m32"

		source_data = self.gen_from_pwntools(source_data)

		source = ""
		source += source_data + "\n"
		source += "int main() {\n"
		source += "}"

		auto_gen = False
		if obj_name is None:
			self.run_cmd("mkdir -p /tmp/.PyGDB")
			obj_name = "/tmp/.PyGDB/%s"%self.gen_rand_str()
			auto_gen = True
		
		cfile_name = obj_name + ".c"
		#print source
		#self.writefile(cfile_name, source)
		#cmdline = "%s %s -o %s %s"%(gcc_path, option, obj_name, cfile_name)
		#res = self.run_cmd(cmdline)
		res = self.compile_cfile(source, gcc_path, option, cfile_name, obj_name)

		if res == True:
			elf_info = ELF(obj_name)

			entry_addr = elf_info.symbols[entry_name]
			main_addr = elf_info.symbols["main"]

			size = main_addr - entry_addr
			data = elf_info.read(entry_addr, size)
		else:
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

	def _asm_(self, asm_info, va):
		if io_wrapper == "zio":
			print("please install pwntools")
			return
		context(arch = self.arch, os = 'linux')
		return asm(asm_info, vma = va)

	def patch_file(self, infile, patch_config, outfile = None, base = 0):
		"""
		patch_config:
		{
			offset: data,
			offset: [data],
			offset: ["asm", data_asm],
			offset: ["data", data],
		}
		"""
		def patch_data(data, offset, content):
			return data[:offset] + content + data[offset + len(content):]

		file_data = self.readfile(infile)
		for addr in patch_config:
			print addr
			value = patch_config[addr]
			data = ""
			if type(value) == str:
				data = value
				
			else:
				if len(value) == 1:
					data = value[0]
				elif value[0] == "data":
					data = value[1]
				elif value[0] == "asm":
					data = self._asm_(value[1], addr)
			file_data = patch_data(file_data, addr - base, data)

		if outfile is None:
			outfile = infile
		self.writefile(outfile, file_data)
		self.run_cmd("chmod +x %s"%outfile)


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

	def load_source(self, arch = "amd64", source = "", text_addr = None, gcc_path = "gcc", obj_name = None):
		option = ""
		self.arch = arch
		if text_addr is not None:
			option += " -Wl,-Ttext-segment=0x%x"%text_addr

		if obj_name is None:
			self.run_cmd("mkdir -p /tmp/.PyGDB")
			obj_name = "/tmp/.PyGDB/%s"%self.gen_rand_str()

		if source == "":
			source = """
#include <stdio.h>
int main() {
	printf("hello world\\n");
	return 0;
}
			"""
		res = self.compile_cfile(source, gcc_path, option, obj_name + ".c", obj_name)
		print "gen objfile @ %s"%obj_name
		self.load_init(target = obj_name)


	def get_lib_base(self, libname):
		data = re.search(".*" + libname, self.procmap())
		if data :
			#print "data:", repr(data.group())
			libaddr = data.group().split("-")[0]
			return int(libaddr, 16)
		else :
			return 0

	def get_thread_id(self):
		thread_num = 0
		addr_v = None

		ret_v = self.do_pygdb_ret("thread")
		#print ret_v
		b_num = self.cut_str(ret_v, "thread is ", " (")
		if b_num :
			b_num = b_num.group().split()[1]
			thread_num = int(b_num)

			addr_v = self.cut_str(ret_v, "(Thread ", " (")
			if addr_v is not None:
				addr_v = int(addr_v, 16)
		return thread_num, addr_v

	def call_s(self, func, args = [], lib_path = "libc.so.6", use_addr = None):
		self.save_context()
		self.call(func, args, lib_path, use_addr)
		self.restore_context()

	def get_target(self):
		return self.target_argv

	def wait_interact(self):
		import signal

		print "<wait for interact> (/continue/exit/quit/c/e/q/ctrl+c)"
		exit_sign = True
		while True:
			try:
				data = raw_input()
				if data.strip().lower() in ["exit", "quit", "e", "q"]:
					exit_sign = True
					break
				elif data.strip().lower() in ["continue", "con", "cont", "c"]: 
					exit_sign = False
					break
			except EOFError:
				print('[+] ' + 'Got EOF while reading in interact')
				break
			except KeyboardInterrupt:
				print('[+] ' + 'Got EOF while reading in interact')
				break
		
		if exit_sign:
			if self.is_local:
				print("[+] kill process")
				os.kill(self.dbg_pid, signal.SIGKILL)
		else:
			target = self.get_target()
			#print "target:", target
			#self.interact()
			self.do_gdb_ret(target)			

	def gdb_interact(self, break_list = [], gdbscript = "", init_file = ".self.init", terminal = None, sudo = True):
		pc = self.get_reg("pc")
		#halt_code = self._asm_("jmp 0x%x"%pc, pc)
		halt_code = self._asm_("jmp $", pc)
		restore_value = self.read_long(pc)
		self.write_mem(pc, halt_code)
		target = self.get_target()

		init_script = ""
		init_script += target + "\n"
		init_script += "set *(unsigned long long *)0x%x=0x%x\n"%(pc, restore_value)
		init_script += "context\n"
		init_script += "\n".join(["b *0x%x"%c for c in break_list]) + "\n"
		init_script += gdbscript.strip()
		self.writefile(init_file, init_script)

		self.detach()

		cmdline = ""
		if sudo == True:
			cmdline += "sudo "
		cmdline += "%s -x %s"%(self.gdb_path, init_file)
		self.run_in_new_terminal(cmdline, terminal = terminal)
		self.wait_interact()
		return

	def setbuf0(self):

		stdin = self.get_symbol_value("stdin")
		stdout = self.get_symbol_value("stdout")
		stderr = self.get_symbol_value("stderr")

		#setvbuf = pygdb.get_symbol_value("setvbuf")
		#pygdb.set_bp(setvbuf)
		#print "stdin:", hex(stdin)
		self.call_s("setvbuf", [stdin, 0, 2, 0])
		self.call_s("setvbuf", [stdout, 0, 2, 0])
		self.call_s("setvbuf", [stderr, 0, 2, 0])

	def execute(self, cmdline, to_string = True):
		data = self.do_gdb_ret(cmdline)
		if to_string == True:
			return data
		else:
			try:
				return int(data, 16)
			except Exception, e:
				return int(data)

	def heapinfo(self,*arg):
		""" Print some information of heap """
		(arena,) = normalize_argv(arg,1)
		mf_angelheap.putheapinfo(arena)

	def heapinfoall(self):
		""" Print some information of multiheap """
		mf_angelheap.putheapinfoall()

	def arenainfo(self):
		""" Print all arena info """
		mf_angelheap.putarenainfo()

	def chunkinfo(self,*arg):
		""" Print chunk information of victim"""
		(victim,) = normalize_argv(arg,1)
		mf_angelheap.chunkinfo(victim)

	def free(self,*arg):
		""" Print chunk is freeable """
		(victim,) = normalize_argv(arg,1)
		mf_angelheap.freeptr(victim)

	def chunkptr(self,*arg):
		""" Print chunk information of user ptr"""
		(ptr,) = normalize_argv(arg,1)
		mf_angelheap.chunkptr(ptr)

	def mergeinfo(self,*arg):
		""" Print merge information of victim"""
		(victim,) = normalize_argv(arg,1)
		mf_angelheap.mergeinfo(victim)

	def force(self,*arg):
		""" Calculate the nb in the house of force """
		(target,) = normalize_argv(arg,1)
		mf_angelheap.force(target)

	def printfastbin(self):
		""" Print the fastbin """
		mf_angelheap.putfastbin()

	def inused(self):
		""" Print the inuse chunk """
		mf_angelheap.putinused()

	def parseheap(self):
		""" Parse heap """
		mf_angelheap.parse_heap()

	def fakefast(self,*arg):
		(addr,size) = normalize_argv(arg,2)
		mf_angelheap.get_fake_fast(addr,size)

	def setHeapFilter(self, *arg):
		(heapFilter, ) = normalize_argv(arg,1)
		mf_angelheap.setHeapFilter(heapFilter)

	def find_ret(self, addr):
		if type(addr) == str:
			addr = self.get_symbol_value(addr)
		old_addr = addr
		while addr - old_addr < 0x10000:
			content = self.execute("x/40i 0x%x"%addr)
			for line in content.split("\n"):
				items = line.strip().split(":\t")
				if len(items) < 2:
					break
				cur_addr = int(items[0].strip().split(" ")[0], 16)
				opcode = items[1].strip().split(" ")[0]
				if opcode.startswith("ret"):
					return cur_addr
				addr = cur_addr