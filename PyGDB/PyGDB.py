
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

		if target_path is not None:
			self.bin_path = target_path

			if (self.arch == None):
				self.arch = self.getarch()

		if self.arch.lower() in ["arch64", "arm"]:
			self.peda_file = os.path.join(peda_dir, "peda-arm.py")
		else:
			self.peda_file = os.path.join(peda_dir, "peda-intel.py")

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
				return "x86-64"
			elif "aarch64" in info :
				capsize = 8
				word = "gx "
				arch = "aarch64"
				return "aarch64"
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

	def set_bp(self, addr, temp = False, hard = False, is_pie = False):
		cmdline = ""
		if temp:
			cmdline = "temp"
		elif hard: 
			cmdline = "hard"

		if is_pie == True:
			addr += self.get_codebase()

		ret_v = self.do_pygdb_ret("set_breakpoint 0x%x %s"%(addr, cmdline))
		b_num = re.search("Breakpoint [\d+] at", ret_v)
		if b_num :
			b_num = b_num.group().split()[1]
			return int(b_num)
		return None

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

	def hexdump(self, addr, count):
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
				data = pygdb.do_gdb_ret("info proc exe")
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

	def hook(self, addr, handler, args, is_pie = False):
		if is_pie == True:
			addr += self.get_codebase()

		if addr in self.hook_map.keys():
			self.remove_hook(addr)

		num = self.set_bp(addr)
		self.hook_map[addr] = [num, handler, args]
		return 

	def clear_hook(self):
		for addr in self.hook_map.keys():
			self.remove_hook(addr)
		self.hook_map = {}

	def remove_hook(self, addr, is_pie = False):
		if is_pie == True:
			addr += self.get_codebase()

		if addr in self.hook_map.keys():
			num = self.hook_map[addr][0]
			self.del_bp(num)
			self.hook_map.pop(addr)

	def run_until(self, addr, is_pie = False):
		if is_pie == True:
			addr += self.get_codebase()

		num = self.set_bp(addr, addr)
		while True:
			pc = self.Continue()
			if pc == -1:
				break

			if pc == addr:
				self.del_bp(addr)
				break

	def Continue(self):
		while True:
			try:
				self._continue()
				pc = self.get_reg("pc")
				if pc in self.hook_map.keys():
					num, handler, args = self.hook_map[pc]
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