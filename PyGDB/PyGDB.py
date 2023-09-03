import mf_angelheap
import traceback
try:
	from pwn import *
	from pwnlib.util import misc
	which = misc.which

	io_wrapper = "pwntools"
except:
	from zio import *
	from zio import which 
	u8 = p8 = lambda x,endian="little":l8(x) if endian == "little" else b8(x)
	u16 = p16 = lambda x,endian="little":l16(x) if endian == "little" else b16(x)
	u32 = p32 = lambda x,endian="little":l32(x) if endian == "little" else b32(x)
	u64 = p64 = lambda x,endian="little":l64(x) if endian == "little" else b64(x)

	io_wrapper = "zio"

import os
import json
import re
import threading
import string
import sys
import commands
import socket
import hashlib

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
		print(all_info)
	return all_info


def PyGDB_unhexdump(data, width = 16):
	final_data = ""
	for line in data.split("\n"):
		if ": " in line:
			line = line[line.index(": ") + 2:]
		elif " " in line:
			line = line[line.index(" ") + 1:]
		line = line.strip()

		#print "line:", line, len(line), width*3
		if len(line) == 0:
			continue

		line = line[:width*3+1]
		final_data += line.replace(" ", "").decode("hex")

	return final_data

def PyGDB_readfile(filename, mode = "rb"):
	with open(filename, mode) as fd:
		return fd.read()

def PyGDB_writefile(filename, data, mode = "wb"):
	with open(filename, mode) as fd:
		return fd.write(data)

def PyGDB_appendfile(filename, data, mode = "ab+"):
	PyGDB_writefile(filename, data, mode)

def PyGDB_hash(data, func = "md5"):
	if func == "md5":
		instants = hashlib.md5()
	elif func == "sha1":
		instants = hashlib.sha1()
	elif func == "sha224":
		instants = hashlib.sha224()
	elif func == "sha256":
		instants = hashlib.sha256()
	elif func == "sha512":
		instants = hashlib.sha512()
	instants.update(data)
	return instants.hexdigest()

#https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
def PyGDB_make_tiny_elf(shellcode, outfile = None, base = None, mode = 32):
	if mode == 32:
		if base is None:
			base = 0x8048000
		elf_bin = ""
		elf_bin += "\x7fELF\x01\x01\x01".ljust(16, '\x00')
		elf_bin += "\x02\x00\x03\x00\x01" + "\x00"*3 + p32(base + 0x54) + "\x34" + "\x00"*3
		elf_bin += "\x00"*8 + "\x34\x00\x20\x00\x01" + "\x00"*3
		elf_bin += "\x00"*4 + "\x01" + "\x00"*7 + p32(base)
		elf_bin += p32(base) + p32(0x54 + len(shellcode))*2
		elf_bin += "\x05\x00\x00\x00\x00\x10\x00\x00"
		elf_bin += shellcode
	else:
		elf_bin = "bad"
	if outfile is not None:
		PyGDB_writefile(outfile, elf_bin)
		do_command("chmod +x " + outfile)
	return elf_bin

class CallException(Exception):
	pass

class PyGDB():
	def __init__(self, target = None, args = [], arch = None):
		self.load_init(target, args, arch)
		mf_angelheap.init_gdb(self)

	def load_init(self, target = None, args = [], arch = None):
		PYGDBFILE = os.path.abspath(os.path.expanduser(__file__))
		#print("PYGDBFILE:", PYGDBFILE)
		while os.path.islink(PYGDBFILE):
			PYGDBFILE = os.path.abspath(os.path.join(os.path.dirname(PYGDBFILE), os.path.expanduser(os.readlink(PYGDBFILE))))
		peda_dir = os.path.join(os.path.dirname(PYGDBFILE), "peda-arm")
		self.pygdb_libpath = os.path.join(os.path.dirname(PYGDBFILE), "lib")
		#print("peda_dir:", peda_dir)

		if target is not None:
			while os.path.islink(target):
				target = os.path.abspath(os.path.join(os.path.dirname(target), os.path.expanduser(os.readlink(target))))
			if os.path.exists(target) and os.access(target, os.X_OK) == False:
				self.run_cmd("chmod +x %s"%target)


		self.globals = {}
		self.priv_globals = {}
		self.priv_globals["lib_handle"] = {}
		self.priv_globals["lib_base"] = {}
		self.priv_globals["lib_path"] = {}
		self.priv_globals["lib_elf"] = {}
		self.arch = arch
		self.bits = None
		self.hook_map = {}
		self.hook_num_map = {}
		self.io = None
		self.gdb_pid = None
		self.dbg_pid = None

		self.safe_call_addr = None
		self.safe_call_ticket = False

		self.is_local = False
		self.code_base = None
		self.libc_base = None
		self.heap_base = None

		self.inject_hook_map = {}
		self.inject_hook_addr = 0x0
		self.inject_hook_base = 0x0
		self.inject_hook_size = 0x0
		self.inject_patch_map = {}
		self.inject_free_map = {}

		self.inject_hook_auto = True

		self.inject_hook_context = {}

		self.inject_hook_globals = {}

		self.core_pygdb_maps = {}

		self.target_argv = ""
		if type(args) == str:
			args = args.split(" ")
		self.target_args = args

		#self.gdb_path = misc.which('gdb-multiarch') or misc.which('gdb')
		self.gdb_path = which('gdb-multiarch') or which('gdb')
		if not self.gdb_path:
			print("'GDB is not installed\n$ apt-get install gdb'")
			exit(0)

		self.bin_path = None
		if target is not None:
			self.bin_path = target

			if (self.arch == None):
				self.arch, self.bits = self.getarch()

		if self.arch is None:
			self.arch = "i386"
			self.bits = 32
		elif self.bits is None:
			if "64" in self.arch:
				self.bits = 64
			else:
				self.bits = 32

		self.arch_args = []
		self.context_regs = []
		self.pc_reg = ""
		self.sp_reg = ""
		if self.is_arm():
			self.peda_file = os.path.join(peda_dir, "peda-arm.py")
			
			self.context_regs = ["sp"]
			if self.bits == 64:
				for i in range(32):
					self.context_regs.append("x%d"%i)
					self.arch_args.append("x%d"%i)
				self.sp_reg = "x29"
				self.pc_reg = "x31"
			else:
				self.sp_reg = "r13"
				self.pc_reg = "r15"
				for i in range(16):
					self.context_regs.append("r%d"%i)
					self.arch_args.append("r%d"%i)
			self.context_regs.append("cpsr")
		else:
			self.peda_file = os.path.join(peda_dir, "peda-intel.py")
			if self.bits == 64:
				self.sp_reg = "rsp"
				self.pc_reg = "rip"
				self.arch_args = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
				self.context_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
			else:
				self.sp_reg = "esp"
				self.pc_reg = "eip"
				self.context_regs = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]


		if self.bits == 64:
			self.pop_asm = "popq"
			self.push_asm = "pushq"
		else:
			self.pop_asm = "pop"
			self.push_asm = "push"

		if self.is_arm():
			self.common_reg = "r0"
		elif self.bits == 64:
			self.common_reg = "rax"
		else:
			self.common_reg = "eax"
		self.mov_asm = "mov"

		self.nop_asm = ""
		if self.is_arm():
			if self.bits == 32:
				self.nop_asm = "mov r0, r0"
			else:
				self.nop_asm = "mov x0, x0"
		else:
			self.nop_asm = "nop"
		self.nop_code = self._asm_(self.nop_asm)


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

		ld_library_path = self.get_ld_library_path().strip()
		if ld_library_path != "":
			ld_library_path += ":"
		ld_library_path += self.pygdb_libpath
		self.set_ld_library_path(ld_library_path)

	def is_arm(self):
		if self.arch.lower() in ["arm", "arch64"]:
			return True
		else:
			return False

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
				return "amd64", 64
			elif "arch64" in info :
				capsize = 8
				word = "gx "
				arch = "arch64"
				return "arch64", 64
			elif "arm" in info :
				capsize = 4
				word = "wx "
				arch = "arm"
				return "arm", 32
			elif "80386" in info:
				word = "wx "
				capsize = 4
				arch = "i386"
				return  "i386", 32
			else:
				return None, None
		else :
			return None, None

	def run_gdb(self):
		if io_wrapper == "zio":
			self.io = zio(self.gdb_argv, print_read = False, print_write = False)
			pids = [self.io.pid, 0]
		else:
			self.io = process(argv = self.gdb_argv)
			pids = proc.pidof(self.io)
		#print(" ".join(self.gdb_argv))
		#print(self.target_args)
		#self.interact()
		self.set_args(self.target_args)

		
		print("gdb pid", pids)
		self.gdb_pid = pids[0]

	def init_gdb(self):
		self.run_gdb()
		#self.do_gdb("set non-stop on")

	def attach(self, target):
		self.is_local = False
		if type(target) == str:
			if ":" in target:
				#self.do_gdb("file")
				self.do_gdb_ret("target remote %s"%target)
				self.target_argv = "target remote %s"%target
			else:
				self.attach_name(target, 0)
		else:
			#self.do_gdb("file")
			print("attach %d"%target)
			self.dbg_pid = target
			print(self.do_gdb_ret("attach %d"%target))
			self.target_argv = "attach %d"%target

	def set_args(self, args):
		if type(args) == str:
			args = args.split(" ")
		self.target_args = args
		self.do_gdb_ret("set args %s"%(" ".join(self.target_args)))

	def get_env(self, name = ""):
		data = self.do_gdb_ret("show environment %s"%name)
		if "not defined." in data:
			return ""
		else:
			return data

	def set_env(self, name = "", value = ""):
		return self.do_gdb_ret("set environment %s %s"%(name, value))

	def set_ld_repload(self, libname):
		return self.set_env("LD_PRELOAD", libname)

	def get_ld_repload(self):
		return self.get_env("LD_PRELOAD")

	def set_ld_library_path(self, ld_path):
		return self.set_env("LD_LIBRARY_PATH", ld_path)

	def get_ld_library_path(self):
		return self.get_env("LD_LIBRARY_PATH")

	def set_call_addr(self, use_addr = None):
		self.safe_call_addr = use_addr# + 0x4

	def start(self):
		self.is_local = True
		result = self.do_gdb_ret("start")
		self.dbg_pid = self.get_dbg_pid()
		if type(self.dbg_pid) != int:
			return ; 
		self.target_argv = "attach %d"%self.dbg_pid

	def run(self, args = None):
		self.is_local = True
		cmdline = "run"
		if args is not None:
			if type(args) == str:
				cmdline += " " + args
			else:
				cmdline += " " + " ".join(args)
		result = self.do_gdb_ret(cmdline)
		self.dbg_pid = self.get_dbg_pid()
		if type(self.dbg_pid) != int:
			return ; 
		self.target_argv = "attach %d"%self.dbg_pid

	def do_pygdb_syn(self):
		while True:
			regs = self.get_regs()
			if type(regs) != dict:
				self.do_pygdb_trim()
			else:
				break

	def do_pygdb_trim(self):
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
			 
	def do_pygdb_ret(self, cmdline):
		self.io.sendline("pyCmdRet %s"%cmdline)

		#print "cmdline:->", cmdline, "<>"

		begin_s = "pyCmd-B{"
		end_s = "}pyCmd-E"
		#self.io.recvuntil(begin_s)
		#data = self.io.recvuntil("}pyCmd-E", drop = True)
		while True:
			data = self.io.recvuntil(end_s)
			pos = data.rfind(begin_s)
			if pos != -1:
				#print "data:<begin>", data, "<end>"
				data = data[pos + len(begin_s):-len(end_s)]
				break
		data = data.decode("hex")
		#print "decode:->", data, "<>"
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
				return ''
			b_pos += len(prefix)
		else:
			b_pos = 0

		if suffix is not None:
			e_pos = data.find(suffix, b_pos)
			if e_pos == -1:
				return ''
		else:
			e_pos = len(data)
		return data[b_pos:e_pos]


	def set_bp(self, addr, temp = False, hard = False, is_pie = False, thread_id = None):

		cmd = "break"
		if hard:
			cmd = "h" + cmd
		if temp:
			cmd = "t" + cmd
		if type(addr) is str:
			addr = self.get_symbol_value(addr)
		else:
			addr = self.real_addr(addr, is_pie)
		addr_str = "*0x%x"%addr

		if thread_id is None:
			cmdline = "%s %s"%(cmd, addr_str)
		else:
			if thread_id == True:
				thread_id = self.get_thread_idv()
			cmdline = "%s %s thread %d"%(cmd, addr_str, thread_id)
			#print("thread_set_bp:", cmdline)
		#print("cmdline:", cmdline)
		ret_v = self.do_gdb_ret(cmdline)
		#print "ret_v:", ret_v
		b_num = re.search("reakpoint \d+ at", ret_v)
		if b_num:
			b_num = b_num.group().split()[1]
			fini_num = int(b_num)

			#print("ret_v:", ret_v)
			addr_v = self.cut_str(ret_v, " %d at "%fini_num)
			if ": " in addr_v:
				addr_v = addr_v.split(": ")[0]
			if " at " in addr_v:
				addr_v = addr_v.split(" at ")[-1]
			if addr_v is not None:
				addr_v = int(addr_v, 16)
			#print("addr_v:", hex(addr_v), fini_num)
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


	def set_mem_bp(self, addr, w_type = "watch", thread_id = None):
		
		if type(addr) is str:
			addr = self.get_symbol_value(addr)
		addr_str = "*0x%x"%addr

		suffix = ""
		if thread_id is None:
			suffix = ""
		else:
			if thread_id == True:
				thread_id = self.get_thread_idv()
			suffix = "thread %d"%(thread_id)
		cmdline = "%s %s %s"%(w_type, addr_str, suffix)

		ret_v = self.do_gdb_ret(cmdline)
		#print ret_v
		b_num = re.search("atchpoint \d+:", ret_v)
		if b_num:
			b_num = b_num.group().split()[1].strip(":")
			fini_num = int(b_num)

			addr_v = self.cut_str(ret_v, "atchpoint %d: *"%fini_num)
			if "\n" in addr_v:
				addr_v = addr_v.split("\n")[0]
			if addr_v is not None:
				addr_v = int(addr_v, 16)

			return fini_num, addr_v
		return None, None

	def watch(self, addr, thread_id = None):
		return self.set_mem_bp(addr, "watch", thread_id = thread_id)

	def awatch(self, addr, thread_id = None):
		return self.set_mem_bp(addr, "awatch", thread_id = thread_id)

	def rwatch(self, addr, thread_id = None):
		return self.set_mem_bp(addr, "rwatch", thread_id = thread_id)

	def set_catch_bp(self, name, catch_type = "syscall"):
		if type(name) is not str:
			name = str(name)
		else:
			name = name

		ret_v = self.do_gdb_ret("catch %s %s"%(catch_type, name))
		#print ret_v
		b_num = re.search("atchpoint \d+ \(", ret_v)
		if b_num:
			b_num = b_num.group().split()[1]
			fini_num = int(b_num)
			return fini_num, "catch_%d"%fini_num
		return None, None

	#read / write / open / etc. / 1
	def catch_syscall(self, info):
		return self.set_catch_bp(info, "syscall")

	#SIGTRAP / SIGINT / all / etc. / 1
	def catch_signal(self, info = "all"):
		return self.set_catch_bp(info, "signal")

	#libc / etc. / 1
	def catch_load(self, regex_str):
		return self.set_catch_bp(regex_str, "load")

	#libc / etc. / 1
	def catch_unload(self, regex_str):
		return self.set_catch_bp(regex_str, "unload")

	def get_code(self, pc = None, count = None, below = False):
		cmdline = ""
		if below:
			if count is None:
				count = 10
			cmdline += "x/%di"%count
			if pc is not None:
				cmdline += " 0x%x"%pc
			else:
				cmdline += " $pc"

			return self.do_gdb_ret(cmdline).strip("\n")
		else:
			if pc is not None:
				cmdline += " %d"%pc
			if count is not None:
				cmdline += " %d"%count
			return self.do_pygdb_ret("get_code %s"%(cmdline)).strip("\n")

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
		#return self.do_pygdb_ret("continue")
		return self.do_gdb_ret("continue")

	def _stepi(self):
		#return self.do_pygdb_ret("continue")
		return self.do_gdb_ret("si")

	def _stepo(self):
		#return self.do_pygdb_ret("continue")
		return self.do_gdb_ret("ni")

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

	def interact(self, prompt = "~> ", simple = True):
		self.do_pygdb("set_interact_mode 1")
		print('[+] ' + 'Switching to interactive mode')
		self.io.sendline("source ~/.gdbinit")

		prompt = term.text.bold_red(prompt)
		self.io.sendline("set prompt %s" % (prompt))

		if simple == True:
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
					go.set()
					break
				except KeyboardInterrupt:
					pass
			print("over")

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
						go.set()
						break

				is_running = False
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				self.interrupt_process()
				self.NopOp()
		while t.is_alive():
			t.join(timeout = 0.1)

	def context_registers(self, split_len = 0x20):
		split_str = "-"*split_len
		print("[%sreg%s]"%(split_str, split_str))
		regs = self.get_regs()
		if type(regs) == dict:
			for reg in self.context_regs:
				print("%-3s: %s"%(reg.upper(), hex(regs[reg])))


	def context_code(self, count = 8, split_len = 0x20):
		split_str = "-"*split_len
		print("[%scode%s]"%(split_str, split_str))
		codeInfo = self.get_code(count = count)
		if type(codeInfo) == str:
			print(codeInfo)


	def context_stack(self, count = 8, split_len = 0x20):
		split_str = "-"*split_len
		print("[%sstack%s]"%(split_str, split_str))
		cur_sp = self.get_reg("sp")
		if type(cur_sp) != str:
			stackInfo = self.get_stack(cur_sp, count)
			if type(stackInfo) == str:
				print(stackInfo)

	def show_context(self, count = 8, split_len = 0x20):
		self.context_registers(split_len)
		self.context_code(count, split_len)
		self.context_stack(count, split_len)

	def interact_pygdb(self, prompt = "~> ", simple = True):

		last_pc = self.get_reg("pc")
		last_data = ""

		self.show_context()
		while True:
			try:
				cont_sign = False
				data = raw_input(prompt).strip()
				if len(data) == 0:
					data = last_data
				if len(data) == 0:
					continue

				last_data = data

				if "quit".startswith(data):
					break
				elif len(data) > 2 and "gdb_interact".startswith(data):
					self.interact()
				elif "continue".startswith(data):
					#print("do continue")
					pc, msg = self.Continue(syn = True)
					#print("pc", hex(pc), msg)
					#if pc == -1:
					#	self.do_pygdb_syn()
					msg = ""
					cont_sign = True
				elif "context".startswith(data):
					self.show_context()
					continue
				elif "kill".startswith(data):
					msg = self.do_gdb_ret(data)
					break
				else:
					msg = self.do_gdb_ret(data)
					sign, pc = self.DealHook(msg)

				cur_pc = self.get_reg("pc")
				if cur_pc != last_pc or cont_sign == True:
					self.show_context()
				last_pc = cur_pc

				if len(msg) != 0:
					sys.stdout.write(msg)
					sys.stdout.flush()
		
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				self.interrupt_process()
				self.do_pygdb_syn()
				self.NopOp()
				self.show_context()


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

	def getlibcbase(self):
		data = re.search(".*libc.*\.so", self.procmap())
		if data :
			libcaddr = data.group().split("-")[0]
			self.libc_base = int(libcaddr, 16)
			self.do_gdb("set $libc={}".format(hex(int(libcaddr, 16))))
			return int(libcaddr, 16)
		else :
			self.libc_base = None
			return 0


	def getprocname(self, relative=False):
		procname = None
		try:
			data = self.execute("info proc exe",to_string=True)
			procname = re.search("exe.*",data).group().split("=")[1][2:-1]
		except:
			data = self.execute("info files",to_string=True)
			if data:
				procname = re.search('Symbols from "(.*)"',data).group(1)
		if procname and relative :
			return procname.split("/")[-1]
		return procname

	def codeaddr(self): # ret (start, end)
		#pat = ".*"
		procname = self.getprocname()
		pat = ".*" + procname
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

	def codebase(self, update = False):
		if update == False and self.code_base is not None:
			return self.code_base
		return self.codeaddr()[0]

	def heapbase(self, update = False):
		if update == False and self.heap_base is not None:
			return self.heap_base
		return self.getheapbase()

	def libcbase(self, update = False):
		if update == False and self.libc_base is not None:
			return self.libc_base
		return self.getlibcbase()

	def heap(self, update = False):
		return self.heapbase(update)

	def libc(self, update = False):
		return self.libcbase(update)

	def code(self, update = False):
		return self.codebase(update)

	def attach_name(self, binary_name, idx = 0):
		b_pos = binary_name.rfind("/")
		if b_pos != -1:
			exe_name = binary_name[b_pos + 1:]
		else:
			exe_name = binary_name
		data = do_command("pidof %s"%exe_name).split(" ")[idx]
		#print("data:", data)
		pid = int(data)
		self.attach(pid)
		return 

	def read_mem(self, addr, size):
		return self.get_mem(addr, size)

	def write_mem(self, addr, data):
		return self.set_mem(addr, data)

	def read_byte(self, addr):
		return u8(self.read_mem(addr, 1))

	def read_word(self, addr, endian = "little"):
		return u16(self.read_mem(addr, 2), endian = endian)

	def read_int(self, addr, endian = "little"):
		return u32(self.read_mem(addr, 4), endian = endian)

	def read_long(self, addr, endian = "little"):
		return u64(self.read_mem(addr, 8), endian = endian)

	def read_pointer(self, addr, endian = "little"):
		if self.bits == 64:
			return self.read_long(addr, endian = endian)
		elif self.bits == 32:
			return self.read_int(addr, endian = endian)
		return 0

	def write_pointer(self, addr, value, endian = "little"):
		if self.bits == 64:
			return self.write_long(addr, value, endian = endian)
		elif self.bits == 32:
			return self.write_int(addr, value, endian = endian)

	def write_byte(self, addr, value):
		self.write_mem(addr, p8(value))

	def write_word(self, addr, value, endian = "little"):
		self.write_mem(addr, p16(value, endian = endian))
	
	def write_int(self, addr, value, endian = "little"):
		self.write_mem(addr, p32(value, endian = endian))
	
	def write_long(self, addr, value, endian = "little"):
		self.write_mem(addr, p64(value, endian = endian))

	def _read_mid_list(self, addr, count, bc = 4, endian = "little"):
		f_i = {}
		f_i[1] = u8
		f_i[2] = u16
		f_i[4] = u32
		f_i[8] = u64

		u_f = lambda x,endian='little':f_i[bc](x, endian = endian)

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

	def _write_mid_list(self, addr, data_list, bc = 4, endian = "little"):
		f_i = {}
		f_i[1] = p8
		f_i[2] = p16
		f_i[4] = p32
		f_i[8] = p64
		#u_f = f_i[bc]
		u_f = lambda x, endian='little':f_i[bc](x, endian = endian)
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

	def hook(self, addr, handler, args = [], hook_ret = None, is_pie = False, thread_id = None):
		addr = self.real_addr(addr, is_pie)

		if addr in self.hook_map.keys():
			self.remove_hook(addr)

		#print("call hook")
		num, addr_v = self.set_bp(addr, thread_id = thread_id)
		if hook_ret is not None and hook_ret != False:
			if hook_ret == True or hook_ret == 1:
				ret_addr = self.find_ret(addr)
			else:
				ret_addr = self.real_addr(hook_ret, is_pie)

			num_ret, addr_v_ret = self.set_bp(ret_addr, thread_id = thread_id)
			self.hook_map[ret_addr] = [num_ret, handler, args, ret_addr, ["OnRet", None, None]]
			self.hook_num_map[num_ret] = ret_addr
		else:
			num_ret, ret_addr = None, None
		self.hook_map[addr_v] = [num, handler, args, addr, ["OnEnter", num_ret, ret_addr]]
		self.hook_num_map[num] = addr_v
		return addr_v

	def hook_mem_read(self, addr, handler, args = [], thread_id = None):
		return self.hook_mem(addr, handler, args, "rwatch", thread_id = thread_id)

	def hook_mem_write(self, addr, handler, args = [], thread_id = None):
		return self.hook_mem(addr, handler, args, "watch", thread_id = thread_id)

	def hook_mem_access(self, addr, handler, args = [], thread_id = None):
		return self.hook_mem(addr, handler, args, "awatch", thread_id = thread_id)

	def hook_mem(self, addr, handler, args = [], w_type = "w", thread_id = None):
		if addr in self.hook_map.keys():
			self.remove_hook(addr)

		if w_type.startswith("a"):
			num, addr_v = self.awatch(addr, thread_id = thread_id)
			w_type = "awatch"
		elif w_type.startswith("r"):
			num, addr_v = self.rwatch(addr, thread_id = thread_id)
			w_type = "rwatch"
		else:
			w_type = "watch"
			num, addr_v = self.watch(addr, thread_id = thread_id)
		num_ret, ret_addr = None, None

		self.hook_map[addr_v] = [num, handler, args, addr, ["OnMem", w_type]]
		self.hook_num_map[num] = addr_v
		return addr_v

	def hook_catch_syscall(self, info, handler, args = []):
		return self.hook_catch(info, handler, args, catch_type = "syscall")

	def hook_catch_signal(self, info, handler, args = []):
		return self.hook_catch(info, handler, args, catch_type = "signal")

	def hook_catch_load(self, info, handler, args = []):
		return self.hook_catch(info, handler, args, catch_type = "load")

	def hook_catch_unload(self, info, handler, args = []):
		return self.hook_catch(info, handler, args, catch_type = "unload")

	def hook_catch(self, info, handler, args = [], catch_type = "syscall"):

		if catch_type.startswith("sys"):
			num, addr_v = self.catch_syscall(info)
			catch_type = "syscall"
		elif catch_type.startswith("sig"):
			num, addr_v = self.catch_signal(info)
			catch_type = "signal"
		elif catch_type.startswith("loa"):
			num, addr_v = self.catch_load(info)
			catch_type = "load"
		elif catch_type.startswith("unl"):
			num, addr_v = self.catch_unload(info)
			catch_type = "unload"
		else:
			num, addr_v = self.catch_syscall(info)
			catch_type = "syscall"
		if num is not None:
			self.hook_map[addr_v] = [num, handler, args, info, ["OnCatch", catch_type]]
			self.hook_num_map[num] = addr_v
		else:
			addr_v = "error"
		return addr_v

	
	def restore_hook(self):
		self.hook_num_map = {}
		for addr in self.hook_map.keys():
			[num, handler, args, addr, hook_info] = self.hook_map[addr_v]
			if hook_info[0] not in ["OnMem", "OnCatch"]:
				num, addr_v = self.set_bp(addr)
				self.hook_map[addr_v] = [num, handler, args, addr, hook_info]
				self.hook_num_map[num] = addr_v
			elif hook_info[0] == "OnMem":
				num, addr_v = self.set_mem_bp(addr, hook_info[1])
				self.hook_map[addr_v] = [num, handler, args, addr, hook_info]	
				self.hook_num_map[num] = addr_v
			elif hook_info[0] == "OnCatch":
				num, addr_v = self.set_catch_bp(addr, hook_info[1])
				self.hook_map[addr_v] = [num, handler, args, addr, hook_info]				
				self.hook_num_map[num] = addr_v
			return 

	def clear_hook(self):
		for addr in self.hook_map.keys():
			self.remove_hook(addr)
		self.hook_map = {}
		self.hook_num_map = {}

	def remove_hook(self, addr, is_pie = False):
		addr = self.real_addr(addr, is_pie)

		if addr in self.hook_map.keys():
			num = self.hook_map[addr][0]
			hook_info = self.hook_map[addr][-1]
			if hook_info[0] not in ["OnMem", "OnCatch"] and hook_info[1] is not None:
				if hook_info[2] in self.hook_map.keys():
					self.del_bp(hook_info[1])
					self.hook_map.pop(hook_info[2])
			self.del_bp(num)
			self.hook_map.pop(addr)
			self.hook_num_map.pop(num)
					
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
					self.hook_num_map.pop(num)
					break

	def run_until(self, addr, is_pie = False, syn = False):
		#print("run_until: 0x%x"%addr)
		#self.interact()
		addr = self.real_addr(addr, is_pie)
		#num, addr_v = self.set_bp(addr)
		num, addr_v = self.set_bp(addr, temp = True, thread_id = True)
		while True:
			try:
				msg = self._continue()
				sign, pc = self.DealHook(msg)
				#print(msg)
				#if "SIGSEGV" in msg:
				#	self.interact()
				#print("addr_v: 0x%x -> 0x%x"%(addr_v, pc))
				if pc == addr_v:
					#self.del_bp(num)
					return pc
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				self.interrupt_process()
				self.NopOp()
				if syn == True:
					self.do_pygdb_syn()
				return -1

	def deal_catch_hook(self, addr_v, msg = ''):
		if addr_v in self.hook_map.keys():
			#print("in deal_catch_hook")
			num, handler, args, addr, hook_info = self.hook_map[addr_v]

			#values = re.findall("alue = 0x[0-9a-fA-F]+\n", msg)
			catch_type = hook_info[1]
			info = "unknown"
			if catch_type in ["syscall"]:
				#infos = re.findall("\(* syscall *\)", msg)
				info_use = self.cut_str(msg, " (", " syscall ").strip()
				syscall_name = self.cut_str(msg, " syscall ", ")").strip()
				if "call to" in info_use:
					info = "OnEnter"
				elif "returned from" in info_use:
					info = "OnRet"
				args = [syscall_name] + args
				#print(info, syscall_name)
			elif catch_type in ["load", "unload"]:
				info_use = self.cut_str(msg, "loaded ", "\n").strip()
				if info_use != "":
					info = info_use.split("loaded ")[-1].strip()
			elif catch_type in ["signal"]:
				info_use = self.cut_str(msg, "(signal ", ")").strip()
				if info_use != "":
					info = info_use.strip()
			#print("handler:", handler)
			ret_v = handler(self, info, *args)
			if ret_v is None or ret_v == True:
				return True
		return False

	def DealHook(self, msg):
		pc = self.get_reg("pc")
		if pc in self.hook_map.keys(): #breakpoint hook
			num, handler, args, addr, hook_info = self.hook_map[pc]
			ret_v = handler(self, hook_info[0], *args)
			if ret_v is None or ret_v == True:
				return True, pc
		else:
			if "atchpoint" in msg and False:
				#print("msg:", msg)
				b_num = re.search("atchpoint \d+:", msg)
				if b_num: #mem breakpoint hook
					#print("in watchpoint")
					b_num = b_num.group().split()[1].strip(":")
					fini_num = int(b_num)

					addr_v = self.cut_str(msg, "atchpoint %d: *"%fini_num)
					if "\n" in addr_v:
						addr_v = addr_v.split("\n")[0]
					if addr_v is not None:
						addr_v = int(addr_v, 16)

					if addr_v in self.hook_map.keys():
						values = re.findall("alue = 0x[0-9a-fA-F]+\n", msg)
						for idx in range(len(values)):
							values[idx] = int(values[idx].split(" = ")[-1].strip(), 16)
						num, handler, args, addr, hook_info = self.hook_map[addr_v]
						ret_v = handler(self, values, *args)
						if ret_v is None or ret_v == True:
							return True, pc
				else:
					b_num = re.search("atchpoint \d+", msg)
					#print("-"*0x10)
					#print(repr(msg))
					#print(b_num)
					#print("-"*0x10)
					if b_num:
						b_num = b_num.group().split()[1].strip()
						#print("b_num:", b_num)
						fini_num = int(b_num)
						addr_v = "catch_%d"%fini_num

						return self.deal_catch_hook(addr_v, msg), pc

			msg = self.do_gdb_ret("info program")
			items = re.findall("breakpoint \d+", msg)
			if len(items) > 0:
				hit_sign = False
				for item in items:
					b_num = int(item.strip().split()[-1])
					#print("b_num:", b_num)
					if b_num in self.hook_num_map.keys():
						#print("b_num:", "in")
						hit_sign = True
						addr_v = self.hook_num_map[b_num]
						if addr_v == "catch_%d"%b_num:
							print("addr_v:", addr_v)
							self.deal_catch_hook(addr_v)
						else:
							num, handler, args, addr, hook_info = self.hook_map[addr_v]
							print("hook_info:", hook_info)
							ret_v = handler(self, [], *args)
				if hit_sign == True:
					return True, pc
				else:
					return False, pc				
			return False, pc

	def go(self, syn = False):
		return self.Continue(syn)

	def Go(self, syn = False):
		return self.Continue(syn)

	def NopOp(self):
		#self.do_pygdb_ret("info terminal")
		pass

	def Continue(self, syn = False):
		while True:
			try:
				msg = self._continue()
				sign, pc = self.DealHook(msg)
				if sign == False:
					if "Program received signal SIGINT" in msg:
						continue
					return pc, msg
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				self.interrupt_process()
				self.NopOp()
				if syn == True:
					self.do_pygdb_syn()
				return -1, "Interrupted"

	def StepI(self, syn = False):
		if True:
			try:
				msg = self.stepi()
				sign, pc = self.DealHook(msg)
				return pc
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				self.interrupt_process()
				self.NopOp()
				if syn == True:
					self.do_pygdb_syn()
				return -1

	def StepO(self):
		pc = self.get_reg("pc")
		asmInfos = self.get_disasm(pc, 2)
		if len(asmInfos) >= 2 and asmInfos[0][1].startswith("call"):
			next_addr = asmInfos[1][0]
			self.run_until(next_addr)
		else:
			msg = self.stepo()
			sign, pc = self.DealHook(msg)

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

		context(arch = self.arch, bits = self.bits, os = 'linux')

		if (addr & 0xfff) != 0:
			size = size + 0x1000 - (addr&0xfff)
		if (size & 0xfff) != 0:
			size = ((size/0x1000) + 1)*0x1000

		prot = self.prot_eval(prot_value)

		shellcode_asm = shellcraft.mmap(addr, size, prot, 0x22, -1, 0)
		shellcode = self._asm_(shellcode_asm)

		pc = self.get_reg("pc")
		old_data = self.read_mem(pc, len(shellcode))
		self.write_mem(pc, shellcode)

		#self.interact()
		self.run_until(pc + len(shellcode))
		self.write_mem(pc, old_data)
		self.set_reg("pc", pc)

		return self.get_result()

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
			addr_use = self.mmap(addr, size, flag)
			if addr_use != addr:
				raise Exception("init_map_config error:", hex(addr), "=>", hex(addr_use))

	def readfile(self, filename, mode = "rb"):
		return PyGDB_readfile(filename, mode)

	def writefile(self, filename, data, mode = "wb"):
		return PyGDB_writefile(filename, data, mode)

	def appendfile(self, filename, data, mode = "ab+"):
		return PyGDB_appendfile(filename, data, mode)

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

	def call_lock(self):
		if self.safe_call_ticket == True:
			return False
		self.safe_call_ticket = True
		return True
		
	def call_unlock(self):
		if self.safe_call_ticket == False:
			return False
		self.safe_call_ticket = False
		return True

	def thread_lock(self):
		#print("thread_lock")
		self.thread_scheduler("on")

	def thread_unlock(self):
		#print("thread_unlock")
		self.thread_scheduler("off")

	def thread_step(self):
		self.thread_scheduler("step")

	def thread_scheduler(self, info):
		self.do_gdb("set scheduler-locking %s"%info)

	def show_scheduler(self):
		return self.do_gdb_ret("show scheduler-locking")

	def call(self, func, args = [], lib_path = "libc", use_addr = None, call_reg = None, debug_list = [], debug_mode = 0):
		#if self.call_lock() == False:
		#	raise CallException("call reenter, flood")

		#print("call realize")
		res = self.call_realize(func, args, lib_path, use_addr, call_reg, debug_list, debug_mode)
		#print("call realize over")

		#if self.call_unlock() == False:
		#	raise CallException("error in call")

		return res

	def get_result(self):
		ret_v = 0
		if self.is_arm():
			ret_v = self.get_reg("r0")
		else:
			if self.bits == 64:
				ret_v = self.get_reg("rax")
			else:
				ret_v = self.get_reg("eax")
		return ret_v

	def call_realize(self, func, args = [], lib_path = "libc", use_addr = None, call_reg = None, debug_list = [], debug_mode = 0):
		"""
		args = [arg0, arg1, arg2, ...]
		"""

		#print("call enter")
		#print(self.get_code(6))

		if io_wrapper == "zio":
			print("please install pwntools")
			return 

		if debug_list is None or debug_list == False:
			debug_list = []
		elif debug_list == True:
			debug_list = [func]
		elif type(debug_list) != list:
			debug_list = [debug_list]

		if type(func) == str:
			if lib_path is not None:
				func_addr = self.get_lib_symbol(func, lib_path)
			else:
				func_addr = self.get_symbol_value(func)
			#func_addr = self.get_lib_symbol(func, lib_path)
		else:
			func_addr = func

		#print("func:", func, hex(func_addr))

		pc = self.get_reg("pc")
		#print("pc", hex(self.get_reg("pc")))
		origin_sp = sp = self.get_reg("sp")

		#self.interact()
		#print("pc-0", hex(self.get_reg("pc")), use_addr)
		args_new = []
		for item in args:
			if type(item) == str:
				sp -= len(item)
				args_new.append(sp)
				self.write_mem(sp, item)
			else:
				args_new.append(item)

		if self.bits == 64:
			#sp -= sp%0x8
			#align by 0x10
			sp -= (sp%0x10)
		else:
			#sp -= sp%0x4
			#align by 0x8
			sp -= (sp%0x8)

		self.set_reg("sp", sp)
		args = args_new

		if use_addr is None:
			use_addr = self.safe_call_addr

		old_data = ""
		if use_addr is None:
			use_addr = pc
		else:
			use_addr += 4
			self.set_reg("pc", use_addr)

		nop_step_info = ""
		if self.is_arm():
			if call_reg is None:
				if self.bits == 32:
					call_reg = "r%d"%len(args)
					nop_step_info = "mov r0, r0"
				else:
					call_reg = "x%d"%len(args)
					nop_step_info = "mov x0, x0"

			call_reg_val = self.get_reg(call_reg)
			self.set_reg(call_reg, func_addr)
			asm_info = ""
			asm_info += nop_step_info + "\n"
			asm_info += "blx %s\n"%call_reg
			asm_info += nop_step_info 
		else:
			if call_reg is None:
				if self.bits == 64:
					call_reg = "rax"
				else:
					call_reg = "eax"

			call_reg_val = self.get_reg(call_reg)
			#print("set", call_reg, hex(func_addr))
			self.set_reg(call_reg, func_addr)
			nop_step_info = "nop"
			asm_info = ""
			asm_info += nop_step_info + "\n"
			asm_info += "call %s\n"%call_reg
			asm_info += nop_step_info
		

		data = self._asm_(asm_info, use_addr)#, arch = self.arch, os = "linux")
		#print data
		disasm_info = self._disasm_(data, vma = use_addr)#, arch = self.arch, os = "linux", byte = None)
		
		#print(disasm_info)
		next_step = 0
		next_addr = 0

		find_sign = False
		asmInfos = self.parse_disasm(disasm_info, mode = 2)
		for items in asmInfos:
			addr = items[0]
			info = (": ".join(items[1:])).strip()
			if find_sign == True:
				next_addr = addr
				break
			else:
				next_step += 1
				if info.startswith("call ") or info.startswith("blx "):
					find_sign = True
					continue

		#print(next_step, hex(next_addr))
		if next_addr == 0:
			print("error next_addr:", hex(next_addr))
			return
		#addr_hex = disasm_info.strip().split("\n")[1].split(":")[0].strip()
		#next_addr = int(addr_hex, 16)

		nop_step_data = asm(nop_step_info, arch = self.arch, os = "linux")
		#print "nop_step_info", nop_step_info
		#print "nop_step_data", nop_step_data.encode("hex")
		
		#sp = self.get_reg("sp")
		old_data = self.read_mem(use_addr-len(nop_step_data), len(nop_step_data) + len(data))
		self.write_mem(use_addr, data)

		repair_stack_offset = 0

		#print [hex(c) for c in args]
		if self.is_arm():
			if self.bits == 32:
				for i in range(len(args)):
					self.set_reg("r%d"%i, args[i])
			else:
				for i in range(len(args)):
					self.set_reg("x%d"%i, args[i])
		else:
			if self.bits == 64:
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


		self.stepi()
		test_step = 3
		while self.get_reg("pc") != use_addr + len(nop_step_data) and test_step > 0:
			self.set_reg('pc', use_addr)
			self.stepi()
			test_step -= 1
		next_step -= 1

		#raw_input(":")
		if func in debug_list:
			#self.stepi()
			#print("use_addr:", hex(use_addr))
			if debug_mode == 0:
				self.interact_pygdb()
			else:
				self.interact()

		#print(self.get_code(4))
		if len(self.hook_map.keys()) != 0:
			#print("here1")
			self.run_until(next_addr)
		else:
			#self.interact()
			for i in range(next_step):
				#print("i:", i)
				#print(self.get_code())
				self.stepo()
			#print("here2")
			if self.get_reg("pc") != next_addr:
				self.run_until(next_addr)
			#print("over")
		
		cur_pc = self.get_reg("pc")
		if cur_pc != next_addr:
			print("cur_pc != next_addr")
			self.interact()

		#self.del_bp(bp_num)
		if old_data != "":
			nop_step_sz = len(nop_step_data)

			#print(hex(use_addr), hex(nop_step_sz))
			self.write_mem(use_addr-nop_step_sz, nop_step_data + old_data[nop_step_sz:])
			self.set_reg("pc", use_addr-nop_step_sz)
			self.stepi()
			self.write_mem(use_addr-nop_step_sz, old_data[:nop_step_sz])
		
		res = self.get_result()
		self.set_reg(call_reg, call_reg_val)
		self.set_reg("pc", pc)
		self.set_reg("sp", origin_sp)

		return res

	def get_symbol_value(self, name):
		#self.interact()
		data = self.do_gdb_ret("print %s"%name)
		#print("print %s"%name)
		#print "data:", data
		#self.interact()
		pos_b = data.find(" 0x")
		if pos_b == -1:
			return 0
		value = data[pos_b+1:].split()[0]
		real_addr = int(value, 16)
		if real_addr == 0:
			print("[!]", name, ":", hex(real_addr))
		#self.interact()
		return real_addr

	def get_lib_symbol(self, name, lib_path = "libc"):

		if io_wrapper == "pwntools":
			return self.get_lib_func(name, lib_path)
		else:
			return self.get_lib_func_dlsym(name, lib_path)
		"""
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
			#self.priv_globals["lib_base"] = {}

		if lib_path not in self.priv_globals["lib_base"].keys():
			args = [lib_path + "\x00", 1] #LAZY
			self.priv_globals["lib_base"][lib_path] = self.call(self.priv_globals["dlopen"], args)
			#print "libc:", hex(self.priv_globals["lib_base"])
		args = [self.priv_globals["lib_base"][lib_path], name + "\x00"]
		real_addr = self.call(self.priv_globals["dlsym"], args)
		if real_addr == 0:
			print("[!]", name, ":", hex(real_addr))
		self.restore_context()
		return real_addr
		"""

	def fix_got(self, got_name, got_addr,  dlsym = True, lib_path = "libc"):
		if dlsym == True:
			real_addr = self.get_lib_symbol(got_name, lib_path)
		else:
			real_addr = self.get_symbol_value(got_name)
		#if real_addr == 0:
		#	print "[!]", got_name, ":", hex(real_addr)
		if self.bits == 64:
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

	def dup_io(self, port = 9999, ip = "0.0.0.0", new_terminal = True, fd_list = [0, 1, 2]):
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

		sockaddr_in = ""
		sockaddr_in += p16(2)
		sockaddr_in += p16(port, endian = 'big')
		sockaddr_in += self.pack_ip4(ip)
		sockaddr_in += p64(0)

		#self.hexdump(data = sockaddr_in)
		#fd_tcp = socket(AF_INET, SOCK_STREAM, 0)
		server = self.call("socket", [2, 1, 0], debug_list = False)
		#print "server", hex(server)

		# setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &flag, len) 
		SOL_SOCKET = 1
		SO_REUSEADDR = 2
		if self.call("setsockopt", [server, SOL_SOCKET, SO_REUSEADDR, p32(1), 4]) == -1:
			print("setsockopt error")
			self.restore_context()
			return  
		#bind(server,(struct sockaddr *)&serv_addr,0x10)
		if (self.call("bind", [server, sockaddr_in, 0x10], debug_list = False) != 0):
			print("bind error")
			self.restore_context()
			return 
		#print "bind", server
		#listen(server,0)
		self.call("listen", [server, 0])
		#print "listen", server

		if new_terminal:
			self.run_in_new_terminal("nc %s %d"%(ip, port), sleep_time = 0.5)
		else:
			print("wait io @ %s:%d"%(ip, port))
		
		#client=accept(server,0,0)
		client = self.call("accept", [server, 0, 0])
		#print "accept", client

		#dup2(client,0)
		#dup2(client,1)
		#dup2(client,2)
		for fd in fd_list:
			self.call("dup2", [client, fd])
		
		"""
		self.call("dup2", [client, 0])
		self.call("dup2", [client, 1])
		self.call("dup2", [client, 2])
		"""
		self.restore_context()


	def call_syscall(self, syscall, args):

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

		if self.bits == 64:
			sp -= sp%8
		else:
			sp -= sp%4

		self.set_reg("sp", sp)
		args = args_new

		context(arch = self.arch, bits = self.bits, os = 'linux')
		#print args
		code_asm = shellcraft.syscall(syscall, *args)
		#print code_asm
		shellcode = asm(code_asm)
		ret_v = self.run_shellcode(shellcode)

		self.set_reg("pc", pc)
		self.set_reg("sp", origin_sp)
		#print "ret_v:", ret_v

		return ret_v

	def call_static(self, func, args, need_parse = True):

		#print "call_static:", func, args
		pc = self.get_reg("pc")
		origin_sp = sp = self.get_reg("sp")

		if need_parse:
			args_new = []
			for item in args:
				if type(item) == str:
					sp -= len(item)
					args_new.append(sp)
					self.write_mem(sp, item)
				else:
					args_new.append(item)

			if self.bits == 64:
				sp -= sp%8
			else:
				sp -= sp%4

			self.set_reg("sp", sp)
			args = args_new

		context(arch = self.arch, bits = self.bits, os = 'linux')
		code_asm = getattr(shellcraft, func)(*args)
		#print code_asm
		shellcode = asm(code_asm)
		ret_v = self.run_shellcode(shellcode)

		self.set_reg("pc", pc)
		self.set_reg("sp", origin_sp)
		#print "ret_v:", ret_v

		return ret_v

	def run_shellcode(self, shellcode):

		if io_wrapper == "zio":
			print("please install pwntools")
			return

		pc = self.get_reg("pc")

		nop_step_info = ""
		if self.is_arm():
			nop_step_info = "mov r0, r0"
		else:
			nop_step_info = "nop"

		nop_step_data = asm(nop_step_info, arch = self.arch, os = "linux")

		old_data = self.read_mem(pc-len(nop_step_data), len(nop_step_data) + len(shellcode))
		self.write_mem(pc, shellcode)

		self.run_until(pc + len(shellcode))
		if old_data != "":
			nop_step_sz = len(nop_step_data)
			self.write_mem(pc-nop_step_sz, nop_step_data + old_data[nop_step_sz:])
			self.set_reg("pc", pc-nop_step_sz)
			self.stepi()
			self.write_mem(pc-nop_step_sz, old_data[:nop_step_sz])

		
		return self.get_result()

	def parse_ip4(self, ip):
		data_list = []
		for item in ip:
			data_list.append(str(u8(item)))
		return ".".join(data_list)

	def pack_ip4(self, ip):
		data = ""
		for item in ip.split("."):
			data += p8(int(item))
		return data



	def dup_io_static(self, port = 9999, ip = "0.0.0.0", new_terminal = True, fd_list = [0, 1, 2]):
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
		sockaddr_in = ""
		sockaddr_in += p16(2)
		sockaddr_in += p16(port, endian = 'big')
		sockaddr_in += self.pack_ip4(ip)
		sockaddr_in += p64(0)

		#self.hexdump(data = sockaddr_in)
		#fd_tcp = socket(AF_INET, SOCK_STREAM, 0)
		server = self.call_syscall('SYS_socket', [2, 1, 0])
		#print "server", server

		# setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &flag, len) 
		SOL_SOCKET = 1
		SO_REUSEADDR = 2
		if self.call_syscall("SYS_setsockopt", [server, SOL_SOCKET, SO_REUSEADDR, p32(1), 4]) == -1:
			print("setsockopt error")
			self.restore_context()
			return  
		#bind(server,(struct sockaddr *)&serv_addr,0x10)
		if (self.call_syscall("SYS_bind", [server, sockaddr_in, 0x10]) != 0):
			print("bind error")
			self.restore_context()
			return 
		#print "bind", server
		#listen(server,0)
		self.call_syscall("SYS_listen", [server, 0])
		#print "listen", server

		if new_terminal:
			self.run_in_new_terminal("nc %s %d"%(ip, port), sleep_time = 0.5)
		else:
			print("wait io @ %s:%d"%(ip, port))
		
		#client=accept(server,0,0)
		client = self.call_syscall("SYS_accept", [server, 0, 0])
		#print "accept", client

		#dup2(client,0)
		#dup2(client,1)
		#dup2(client,2)
		for fd in fd_list:
			self.call_static("dup2", [client, fd])
		
		"""
		self.call_static("dup2", [client, 0])
		self.call_static("dup2", [client, 1])
		self.call_static("dup2", [client, 2])
		"""

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
		data = do_command(cmd_line)
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
		cmdline = "%s %s %s -o %s"%(gcc_path, infile, option, outfile)
		res = self.run_cmd(cmdline)
		#print("compile_cmd:", cmdline)
		if ("error: " not in res.lower()):
			return True
		else:
			print(res)
			return False

	def gen_payload(self, source_data, gcc_path = "gcc", option = "", obj_name = None):
		
		if io_wrapper == "zio":
			print("please install pwntools")
			return
		context(arch = self.arch, bits = self.bits, os = 'linux')

		if option == "":
			option += " -fno-stack-protector"

		if self.is_arm() == False:
			if self.bits != 64:
				option += " -m32"

		source_data = self.gen_from_syscall(source_data)
		source_data = self.gen_from_pwntools(source_data)
		source_data = self.gen_from_embed(source_data)
		source_data = self.gen_from_asm(source_data)
		source_data = self.gen_from_stack_value(source_data)

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
			elf_info = ELF(obj_name, checksec = False)

			entry_addr = elf_info.symbols[entry_name]
			main_addr = elf_info.symbols["main"]

			size = main_addr - entry_addr
			data = elf_info.read(entry_addr, size)
		else:
			data = "error"
			raise Exception("error")

		if auto_gen:
			if os.path.exists(cfile_name):
				os.unlink(cfile_name)
			if os.path.exists(obj_name):
				os.unlink(obj_name)

		return data

	def hash(self, data, func = "md5"):
		return PyGDB_hash(data, func)

	def write_plt_got(self, func_addr, plt_addr, got_addr):
		addr_size = self.bits / 8
		if self.bits == 64:
			p_f = p64
			ptr_asm = "QWORD PTR"  
		else:
			p_f = p32
			ptr_asm = "DWORD PTR"

		#print("got_addr:", hex(got_addr))
		#print("plt_addr:", hex(plt_addr))
		offset = got_addr - (plt_addr + 6)
		if self.is_arm():
			if offset >= 0:
				offset_str = "+0x%x"%offset
			else:
				offset_str = "-0x%x"%ord(offset)
			plt_data = self._asm_("mov pc %s [pc%s]"%(ptr_asm, offset_str), vma = plt_addr)
		else:
			if offset >= 0:
				offset_str = "+0x%x"%offset
			else:
				offset_str = "-0x%x"%abs(offset)
			if self.bits == 64:
				plt_data = self._asm_("jmp %s [rip%s]"%(ptr_asm, offset_str), vma = plt_addr)
				#print(self._disasm_(plt_data, vma = plt_addr))
				#real_data = "\xff\x25" + p_f(got_addr - (plt_addr + 6))
				#print(self._disasm_(real_data, vma = plt_addr))
			else:
				plt_data = self._asm_("jmp %s [eip%s]"%(ptr_asm, offset_str), vma = plt_addr)

		got_data = p_f(func_addr)
		self.write_mem(plt_addr, plt_data)
		#print("write got:", hex(got_addr), hex(elf_info.symbols[key]))
		self.write_mem(got_addr, got_data)

	def load_lib_plt(self, lib_name, func_list = [], plt_base = None, got_base = None, config = True):
		#if self.inject_hook_base == 0:
		#	self.auto_config_inject()
		plt_maps = {}
		#print("here:", lib_name)
		if os.path.exists(lib_name):
			#print("load_lib_plt:", lib_name)
			elf_info = ELF(lib_name, checksec = True)

			use_func_list = []
			for key in elf_info.symbols.keys():
				#print(key in func_list, key, func_list)
				if key in func_list:
					use_func_list.append(key)

			sym_count = len(use_func_list)

			#print("func_list:", func_list)
			#print("sym_count:", sym_count)
			addr_size = self.bits / 8
			if sym_count > 0:
				if plt_base is None:
					plt_base = self.inject_hook_alloc(sym_count*8, align = True)

				if got_base is None:
					got_base = self.inject_hook_alloc(sym_count*addr_size, align = True)

				if plt_base is None:
					raise Exception("plt addr error")
				if got_base is None:
					raise Exception("got addr error")

				#print(lib_name, "load_lib")
				lib_base = self.load_lib(lib_name)
				if lib_base == 0:
					raise Exception("load lib error")
				#print(lib_name, "base:", hex(lib_base))
				elf_info.address = lib_base
				idx = 0
				for key in use_func_list:
					got_addr = got_base + idx * addr_size
					plt_addr = plt_base + idx * 8
					self.write_plt_got(elf_info.symbols[key], plt_addr, got_addr)
					plt_maps[key] = plt_addr
					idx += 1
		else:
			data = "error"
			raise Exception("error not exists:", lib_name)
		if config == True:
			self.config_inject_map(globals_map = plt_maps)
		return plt_maps, lib_base

	def load_cfile_lib(self, filename, plt_base = None, got_base = None, gcc_path = "gcc", option = "", obj_name = None, update = True):
		source_data = self.readfile(filename)
		return self.load_source_lib(source_data, plt_base = plt_base, got_base = got_base, gcc_path = gcc_path, option = option, obj_name = obj_name, update = update)

	def load_source_lib(self, source_data, plt_base = None, got_base = None, gcc_path = "gcc", option = "", obj_name = None, update = True):
		if len(self.core_pygdb_maps.keys()) == 0:
			self.core_inject_init(show = False)

		auto_gen = False
		if obj_name is None:
			self.run_cmd("mkdir -p ./.PyGDB")
			obj_name = "./.PyGDB/%s"%self.hash(source_data)
			auto_gen = True

		func_list = []

		source_data = self.gen_from_syscall(source_data)
		source_data = self.gen_from_pwntools(source_data)
		source_data = self.gen_from_embed(source_data)
		source_data = self.gen_from_asm(source_data)
		source_data = self.gen_from_stack_value(source_data)
		source_data = self.gen_from_common(source_data)
		func_list = self.extract_func(source_data)

		if auto_gen == False or os.path.exists(obj_name) == False or update == True:
		
			context(arch = self.arch, bits = self.bits, os = 'linux')

			if option == "":
				option += " -fPIC -shared -I %s -L %s -lpygdb"%(self.pygdb_libpath, self.pygdb_libpath)

			if self.is_arm() == False:
				if self.bits != 64:
					option += " -m32"

			source = ""
			source += source_data
			
			cfile_name = obj_name + ".c"
			#print source
			#self.writefile(cfile_name, source)
			#cmdline = "%s %s -o %s %s"%(gcc_path, option, obj_name, cfile_name)
			#res = self.run_cmd(cmdline)
			if os.path.exists(obj_name):
				os.unlink(obj_name)
			res = self.compile_cfile(source, gcc_path, option, cfile_name, obj_name)

			if res == False:
				raise Exception("compile_cfile error")
			#print("rers:", res)
			#"""
			if auto_gen:
				if os.path.exists(cfile_name):
					os.unlink(cfile_name)
			#"""

		plt_maps, lib_base = self.load_lib_plt(obj_name, func_list = func_list, plt_base = plt_base, got_base = got_base)

		#"""
		if auto_gen:
			if os.path.exists(obj_name):
				os.unlink(obj_name)
		#"""

		return plt_maps, lib_base

	def gen_inject_asm(self, code_asm):
		if io_wrapper == "zio":
			print("please install pwntools")
			return
		context(arch = self.arch, bits = self.bits, os = 'linux')
		#print("code_asm:")
		#print(code_asm)
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

	def _asm_(self, asm_info, vma = None):
		if io_wrapper == "zio":
			print("please install pwntools")
			return
		context(arch = self.arch, bits = self.bits, os = 'linux')

		asm_info = asm_info.strip()
		new_asm_code_list = []
		for line in asm_info.strip().split("\n"):
			line = line.strip()
			if line.startswith(";") or line.startswith("//"):
				continue
			line = self.remove_pairs(line, ["<", ">"]).split(" #")[0].strip()
			new_asm_code_list.append(line)
		asm_info = "\n".join(new_asm_code_list)

		return asm(asm_info, vma = vma)

	def _disasm_(self, data, vma = None):
		if io_wrapper == "zio":
			print("please install pwntools")
			return
		context(arch = self.arch, bits = self.bits, os = 'linux')
		return disasm(data, vma = vma, byte = None)

	def patch_data(self, data, offset, content):
		if offset + len(content) > len(data):
			print("out of bound")
			return data
		return data[:offset] + content + data[offset + len(content):]

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

		file_data = self.readfile(infile)
		for addr in patch_config:
			#print(addr)
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
			file_data = self.patch_data(file_data, addr - base, data)

		if outfile is None:
			outfile = infile
		self.writefile(outfile, file_data)
		self.run_cmd("chmod +x %s"%outfile)


	def gen_from_pwntools(self, c_source, show = False):
		context.update(arch = self.arch, bits = self.bits, os = 'linux')
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
					voto_info = voto_info.replace("  ", " ")
				voto_info = voto_info.strip()
				name = voto_info.split("(")[0].split(" ")[-1].strip()

				arg_info = voto_info
				while True:
					if "(" in arg_info:
						arg_info = arg_info.split("(")[1]
					elif ")" in arg_info:
						arg_info = arg_info.split(")")[0]
					else:
						break
				arg_info_list = []
				#print("arg_info:", arg_info)
				args_count = len(arg_info.split(","))
				code_asm = ""
				if args_count > 0:
					if "i386" in self.arch.lower():
						#code_asm = getattr(shellcraft, name)(self.arch_args[:args_count])
						args_name = ["ebx", "ecx", "edx", "edi", "esi", "ebp"]

						real_args = []
						cur_idx = 0
						for arg in arg_info.split(","):
							arg = arg.strip()
							if arg.isdigit():
								real_args.append(int(arg))
							elif arg.startswith("0x"):
								real_args.append(int(arg, 16))
							elif arg[0] in ["\'", "\""] and arg[-1] in ["\'", "\""]:
								real_args.append(arg)
								real_args.append(arg[1:-1].strip())
							else:
								reg = args_name[cur_idx]
								real_args.append(reg)
								raise Exception("args error '%s' in %s" % (arg, name))
						print("real_args:", name, real_args)
						code_asm += getattr(shellcraft, name)(*(real_args))
					else:
						#print getattr(shellcraft, name)("rdi", "rsi")
						#print shellcraft.write(*(self.arch_args[:args_count]))
						#print getattr(shellcraft, name)(*(self.arch_args[:args_count]))
						args_name = self.arch_args
						real_args = []
						cur_idx = 0
						for arg in arg_info.split(","):
							arg = arg.strip()
							if arg.isdigit():
								real_args.append(int(arg))
							elif arg.startswith("0x"):
								real_args.append(int(arg, 16))
							elif arg[0] in ["\'", "\""] and arg[-1] in ["\'", "\""]:
								real_args.append(arg[1:-1].strip())
							else:
								#print("error")
								raise Exception("args error '%s' in %s" % (arg, name))
						#print("real_args:", real_args)
						code_asm = getattr(shellcraft, name)(*(real_args))
				else:
					code_asm = getattr(shellcraft, name)()
				if show:
					print("code_asm:", name)
					print(code_asm)
				inject_asm = self.gen_inject_asm(code_asm)
				
				#prefix_list.append(voto_info + ";")
				define_content = ""
				define_content += "{\n"
				define_content += inject_asm + "\n"
				define_content += "}"

				mid_list.append(define_content)

			else:
				mid_list.append(line)
		new_content = ""
		new_content += "\n".join(prefix_list + mid_list + suffix_list)

		return new_content

	def gen_from_embed(self, c_source, show = False):
		name_map = {}
		start_model = "gen_from_embed("

		embed_functions = {}
		embed_functions["strlen"] = """
int strlen(char *data) {
	int i;
	for(i = 0; ; i++)
		if (data[i] == 0)
			break;
	return i;
}
"""
		embed_functions["memset"] = """
void memset(char *data, char ch, int size) {
	int i;
	for(i = 0; i < size; i++)
		data[i] = ch;
}
"""
		embed_functions["mov_val_rax"] = """
long int mov_val_rax(long int data) {
	return data;
}
"""
		embed_functions["mov_addr_rax"] = """
char* mov_addr_rax(void* data) {
	return (char *)data;
}
"""

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
					voto_info = voto_info.replace("  ", " ")
				voto_info = voto_info.strip()
				name = voto_info.split("(")[0].split(" ")[-1].strip()

				if name in embed_functions.keys():
					code_asm = embed_functions[name].strip()
					if show:
						print("code_asm:", name)
						print(code_asm)
					inject_asm = code_asm

					voto_info = code_asm.split("\n")[0].strip("{").strip()
					prefix_list.append(voto_info + ";")

					define_content = ""
					define_content += inject_asm + "\n"

					suffix_list.append(define_content.strip().strip())

			else:
				mid_list.append(line)
		new_content = ""
		new_content += "\n".join(prefix_list + mid_list + suffix_list)

		return new_content

	def gen_from_asm(self, c_source, show = False):
		context(arch = self.arch, bits = self.bits, os = 'linux')

		name_map = {}
		start_model = "gen_from_asm("

		prefix_list = []
		suffix_list = []
		mid_list = []
		for line in c_source.split("\n"):
			line_new = line.strip()
			if line_new.startswith(start_model):
				pos_e = line_new.rfind(")")
				if pos_e == -1:
					continue
				asm_code = line_new[len(start_model):pos_e].replace("\t", " ")
				while asm_code.find("  ") != -1:
					asm_code = asm_code.replace("  ", " ")
				
				if asm_code[0] in ["\'", "\""] and asm_code[-1] in ["\'", "\""]:
					asm_code = asm_code[1:-1].strip()
				asm_code = asm_code.strip()
				asm_code = asm_code.replace("\\n", "\n")
				asm_code = asm_code.replace(";", "\n")

				#print("asm_code:")
				#print(repr(asm_code))
				inject_asm = self.gen_inject_asm(asm_code)

				define_content = inject_asm

				mid_list.append(define_content.strip())

			else:
				mid_list.append(line)
		new_content = ""
		new_content += "\n".join(prefix_list + mid_list + suffix_list)

		return new_content

	def gen_from_syscall(self, c_source, show = False):

		context(arch = self.arch, bits = self.bits, os = 'linux')
		name_map = {}
		start_model = "gen_from_syscall("

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
					voto_info = voto_info.replace("  ", " ")
				voto_info = voto_info.strip()
				name = voto_info.split("(")[0].split(" ")[-1].strip()

				arg_info = voto_info
				while True:
					if "(" in arg_info:
						arg_info = arg_info.split("(")[1]
					elif ")" in arg_info:
						arg_info = arg_info.split(")")[0]
					else:
						break
				arg_info_list = []
				#print("arg_info:", arg_info)
				args_count = len(arg_info.split(","))
				code_asm = ""
				if args_count > 0:
					if "i386" in self.arch.lower():
						#code_asm = getattr(shellcraft, name)(self.arch_args[:args_count])
						args_name = ["ebx", "ecx", "edx", "edi", "esi", "ebp"]

						stack_arg_list = args_name[:args_count]

						for i in range(len(stack_arg_list)):
							code_asm += "push %s\n"%stack_arg_list[i]
							code_asm += "mov %s, dword ptr [esp + 0x%x]\n"%(stack_arg_list[i], (i+1)*4)
						#code_asm += getattr(shellcraft, name)(*(real_args))
						code_asm += "push SYS_%s\n"%name
						code_asm += "pop eax\n"
						code_asm += "int 0x80\n"
						for i in range(len(stack_arg_list)-1, -1, -1):
							code_asm += "pop %s\n"%stack_arg_list[i]


					else:
						#print getattr(shellcraft, name)("rdi", "rsi")
						#print shellcraft.write(*(self.arch_args[:args_count]))
						#print getattr(shellcraft, name)(*(self.arch_args[:args_count]))
						args_name = self.arch_args
						stack_arg_list = args_name[:args_count]
						#real_args = []
						code_asm += "pushq SYS_%s\n"%name
						code_asm += "popq rax\n"
						code_asm += "syscall\n"
						#code_asm = getattr(shellcraft, name)(*(stack_arg_list))
				else:
					#code_asm = getattr(shellcraft, name)()
					code_asm += "push SYS_%s\n"%name
					code_asm += "pop rax\n"
					code_asm += "syscall\n"
				
				if show:
					print("code_asm:", name)
					print(code_asm)
				inject_asm = self.gen_inject_asm(code_asm)
				
				#voto_info = voto_info.split(name)[0] + name + "(%s)"%(" ,".join(arg_info_list))
				if voto_info.startswith(name):
					voto_info = "int " + voto_info
				prefix_list.append(voto_info + ";")

				define_content = ""
				define_content += voto_info + " {\n"
				define_content += inject_asm + "\n"
				define_content += "}"

				suffix_list.append(define_content.strip())

			else:
				mid_list.append(line)
		new_content = ""
		new_content += "\n".join(prefix_list + mid_list + suffix_list)

		return new_content


	def gen_from_stack_value(self, c_source, show = False):
		context(arch = self.arch, bits = self.bits, os = 'linux')

		name_map = {}
		start_model = "gen_from_stack_value("

		prefix_list = []
		suffix_list = []
		mid_list = []
		for line in c_source.split("\n"):
			line_new = line.strip()
			if line_new.startswith(start_model):
				pos_e = line_new.rfind(")")
				if pos_e == -1:
					continue

				pos_b = line_new.rfind(",")
				if pos_b == -1:
					continue

				voto_info = line_new[len(start_model):pos_e].replace("\t", " ")
				while voto_info.find("  ") != -1:
					voto_info = voto_info.replace("  ", " ")
				voto_info = voto_info.strip()
				name = voto_info.split("(")[0].split(" ")[-1].strip()

				dataInfo = line_new[pos_b+1:pos_e].strip()
				
				if asm_code[0] in ["\'", "\""] and asm_code[-1] in ["\'", "\""]:
					asm_code = asm_code[1:-1]

				stackContent = self.gen_stack_value(name, dataInfo)
				mid_list.append(stackContent.strip())

			else:
				mid_list.append(line)
		new_content = ""
		new_content += "\n".join(prefix_list + mid_list + suffix_list)

		return new_content

	def core_context_header(self):

		regs_info_list = []
		if self.is_arm() == True:
			aligin_val = 0
		else:
			aligin_val = 1
		for reg in self.context_regs:
			if reg in [self.sp_reg, self.pc_reg]:
				continue
			regs_info_list.append("	long int %s;"%reg)
		if self.is_arm() == False:
			regs_info_list.append("	long int eflags;")
			
		if len(self.context_regs) % 2 != aligin_val:
			regs_info_list.append("	long int reserved;")
		regs_info_list.append("	long int %s;"%self.sp_reg)
		regs_info_list.append("	long int %s;"%self.pc_reg)
		header_content = """
typedef struct _context {
%s
} context;"""%("\n".join(regs_info_list))
		return header_content.strip()

	def context_header(self):

		regs_info_list = []
		if self.is_arm() == True:
			aligin_val = 0
		else:
			aligin_val = 1
		for reg in self.context_regs:
			if reg in [self.sp_reg, self.common_reg]:
				continue
			regs_info_list.append("	long int %s;"%reg)
		if self.is_arm() == False:
			regs_info_list.append("	long int eflags;")

		if len(self.context_regs) % 2 != aligin_val:
			regs_info_list.append("	long int reserved;")
		regs_info_list.append("	long int %s;"%self.common_reg)
		regs_info_list.append("	long int %s;"%self.sp_reg)
		header_content = """
typedef struct _context {
%s
} context;"""%("\n".join(regs_info_list))
		return header_content.strip()

	def gen_from_common(self, c_source, show = False):
		context(arch = self.arch, bits = self.bits, os = 'linux')

		name_map = {}
		start_model = "#include "

		prefix_list = []
		suffix_list = []
		mid_list = []
		for line in c_source.split("\n"):
			line_new = line.strip()
			if line_new.startswith(start_model):

				while line_new.find("  ") != -1:
					line_new = line_new.replace("  ", " ")
				header = line_new.replace(start_model, "").replace("\t", " ").strip()
				
				if header[0] in ["\'", "\"", "<"] and header[-1] in ["\'", "\"", ">"]:
					header = header[1:-1]
				if header == "pygdb/context.h":
					mid_list.append(self.core_context_header())
				else:
					mid_list.append(line)
			else:
				mid_list.append(line)
		new_content = ""
		new_content += "\n".join(prefix_list + mid_list + suffix_list)

		return new_content

	def extract_func(self, c_source):
		name_list = []
		for line in c_source.split("\n"):
			line_new = line.strip()
			if "{" in line_new:
				line_new = line_new.split("{")[0].strip()
			#print("line_new:", line_new)
			if line_new.endswith(")"):
				pos_e = line_new.rfind(")")
				if pos_e == -1:
					continue
				voto_info = line_new[:pos_e].replace("\t", " ")
				while voto_info.find("  ") != -1:
					voto_info = voto_info.replace("  ", " ")
				voto_info = voto_info.strip()
				#print("voto_info:", voto_info)
				name = voto_info.split("(")[0].split(" ")[-1].strip()

				if len(name) == 0:
					continue
				if name not in ["if", "while", "for"] and name not in name_list:
					name_list.append(name)
		return name_list

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
		print("gen objfile @ %s"%obj_name)
		self.load_init(target = obj_name)


	def get_lib_base(self, libname, update = False):
		if update == False:
			if libname in self.priv_globals["lib_base"].keys():
				return self.priv_globals['lib_base'][libname]

		if ".*" not in libname:
			pattern = ".*" + libname + ".*"
		else:
			pattern = libname
		data = re.search(pattern, self.procmap())
		#print(data)
		if data:
			libaddr = data.group().split("-")[0]
			self.priv_globals['lib_base'][libname] = int(libaddr, 16)
			self.priv_globals['lib_handle'][libname] = 0

			lib_path = data.group().split(" ")[-1]
			#print("lib_path:", lib_path)
			self.priv_globals['lib_path'][libname] = lib_path
			return int(libaddr, 16)
		else :
			return 0

	def load_lib(self, lib_path, update = False):
		if update == False and lib_path in self.priv_globals["lib_base"]:
			return self.priv_globals["lib_base"][lib_path]

		self.save_context()
		if "dlopen" not in self.priv_globals.keys():
			if "__libc_dlopen_mode" not in self.priv_globals.keys():
				self.priv_globals["__libc_dlopen_mode"] = self.get_symbol_value("__libc_dlopen_mode")
				self.priv_globals["__libc_dlsym"] = self.get_symbol_value("__libc_dlsym")
			
			libdl_base = self.get_lib_base("libdl")
			#print("libdl base:", hex(libdl_base))
			if libdl_base == 0:
				libdl = "libdl.so.2"
				args = [libdl + "\x00", 0x80000001]
				libdl_handle = self.call(self.priv_globals["__libc_dlopen_mode"], args)#, debug_list = True)
				self.priv_globals["dlopen"] = self.get_symbol_value("dlopen")
				self.priv_globals["dlsym"] = self.get_symbol_value("dlsym")
				#self.priv_globals["lib_base"] = {}
			else:
				self.priv_globals["dlopen"] = self.get_lib_func("dlopen", "libdl")
				self.priv_globals["dlsym"] = self.get_lib_func("dlsym", "libdl")

				#print("dlopen", hex(self.priv_globals["dlopen"]))
				#print("dlsym", hex(self.priv_globals["dlsym"]))
				#self.gdb_interact(gdbscript_pre = "file /bin/cat")

		lib_full_path = os.path.realpath(lib_path)
		#print("lib_full_path:", lib_full_path)
		args = [lib_full_path + "\x00", 1] #LAZY
		handle = self.call(self.priv_globals["dlopen"], args)#, debug_list = debug_list)
		#print("handle:", lib_full_path, hex(handle))
		if handle == 0:
			self.interact()
		self.priv_globals["lib_handle"][lib_path] = handle
		self.priv_globals["lib_base"][lib_path] = self.read_pointer(handle)
		self.priv_globals['lib_path'][lib_path] = lib_path
		#print(self.priv_globals["lib_base"])
		#print "lib_base:", hex(self.priv_globals["lib_base"][lib_path])
		self.restore_context()
		return self.priv_globals["lib_base"][lib_path]

	def get_lib_func(self, name, libname = "libc"):
		if libname not in self.priv_globals['lib_path'].keys():
			self.get_lib_base(libname)
			if libname not in self.priv_globals['lib_path'].keys():
				self.load_lib(libname)

		if libname not in self.priv_globals["lib_elf"]:
			if io_wrapper == "zio":
				print("please install pwntools")
			lib_path = self.priv_globals['lib_path'][libname]
			self.priv_globals["lib_elf"][libname] = ELF(lib_path, checksec = False)

		elf_info = self.priv_globals["lib_elf"][libname]
		return elf_info.symbols[name] + self.priv_globals["lib_base"][libname]

	def get_lib_func_dlsym(self, name, libname = "libc"):

		if libname not in self.priv_globals['lib_path'].keys():
			self.get_lib_base(libname)
			if libname not in self.priv_globals['lib_path'].keys():
				self.load_lib(libname)
		self.save_context()
		args = [self.priv_globals["lib_handle"][lib_path], name + "\x00"]
		real_addr = self.call(self.priv_globals["dlsym"], args)
		if real_addr == 0:
			print("[!]", name, ":", hex(real_addr))
		self.restore_context()
		return real_addr

	def get_thread_id(self):
		thread_num = 0
		addr_v = None

		ret_v = self.do_gdb_ret("thread")
		#print ret_v
		b_num = self.cut_str(ret_v, "thread is ", " (")
		if b_num:
			thread_num = int(b_num.strip())

			addr_v = self.cut_str(ret_v, "(Thread ", " (")
			if addr_v is not None:
				addr_v = int(addr_v, 16)
		return thread_num, addr_v

	def get_thread_idv(self):
		thread_num = 0
		addr_v = None

		ret_v = self.do_gdb_ret("thread")
		#print ret_v
		b_num = self.cut_str(ret_v, "thread is ", " (")
		if b_num:
			thread_num = int(b_num.strip())
		return thread_num

	"""
	def call_s(self, func, args = [], lib_path = "libc.so.6", use_addr = None):
		#self.save_context()
		self.invoke_s(self.call, func, args, lib_path, use_addr)
		#self.restore_context()
	"""

	def parse_disasm(self, asmInfo, parse = True, mode = 1):
		asmInfo = asmInfo.strip("\n")
		#print("asmInfo:")
		#print(asmInfo)
		ret_values = []
		for line in asmInfo.split("\n"):
			if len(line.strip()) == 0:
				continue
			if mode == 1:
				items = line.split(" 0x")
				if len(items) < 1:
					break
				line = (" 0x".join(items[1:])).strip()
				if parse == False:
					line = line.split(" #")[0]
				items = line.split(":\t")
				if len(items) < 2:
					continue
				#print(repr(items))
				#print(items[0].replace("\t", " ").split(" ")[0])
				addr = int(items[0].replace("\t", " ").split(" ")[0], 16)
				info = ":\t".join(items[1:])
			else:
				items = line.strip().split(": ")
				if len(items) < 2:
					continue
				addr = int(items[0].strip(), 16)
				info = (": ".join(items[1:])).strip()
			ret_values.append([addr, info.strip()])
		return ret_values 

	def get_disasm(self, addr, length = 1, parse = True, mode = "line", base = None):
		if length > 0x400 and length > addr:
			mode = "code"
			length = length - addr

		if mode == "line" and base is None:
			cmdline = "x/%di 0x%x"%(length, addr)
			info = self.do_gdb_ret(cmdline)#.strip()
			mode = 1
		else:
			if base is None or base is True:
				base = addr
			elif base == False:
				base = 0
			data = self.read_mem(addr, length)
			info = self._disasm_(data, base)
			mode = 2
		#print("cmdline:", cmdline)
		#print("info:")
		#print(info)
		return self.parse_disasm(info, parse, mode)

	def get_backtrace(self, level = None):
		#self.interact()
		info = self.do_gdb_ret("bt")
		addr_list = []
		items = info.strip().split("\n")
		if level is not None:
			items = items[:level]
		for item in items:
			#self.interact()
			if " in " in item:
				#print("item:", item.split(" in ")[0].strip().replace("\t", " ").split("  "))
				addr = item.split(" in ")[0].strip().replace("\t", " ").split(" ")[-1]
				addr_list.append(int(addr, 16))
			elif " at " in item:
				addr_symbol = item.split(" at ")[0].strip().replace("\t", " ").split("  ")[1].split(" ")[0]
				addr = self.get_symbol_value(addr_symbol)
				addr_list.append(addr)
			else:
				addr_list.append(-1)
		return addr_list

	def chg_thread(self, thread_id):
		cur_thread_id = self.get_thread_idv()
		#print("chg_thread:", cur_thread_id, thread_id)
		return self.do_gdb_ret("thread %d"%thread_id)

	def skip_reason(self, skip_sign):
		if skip_sign == 1:
			return "handler"
		elif skip_sign == 2:
			return "record_maps"
		elif skip_sign == 3:
			return "addr_list"
		else:
			return "unknown_%d"%skip_sign

	def trace(self, b_addr = None, e_addr = None, logPattern = "trace", record_maps = [], skip_list = [], byThread = False, asmCode = True, appendMode = False, is_pie = False, rec_base = 0x0, skip_loops = True, trace_handler = None, function_mode = False, show = True, oneThread = True, level_mode = True, start_level = 0, level_str = "  "):

		if b_addr is not None:
			b_addr = self.real_addr(b_addr, is_pie)
		if e_addr is not None:
			e_addr = self.real_addr(e_addr, is_pie)

		pc = self.get_reg("pc")
		if b_addr is not None and pc != b_addr:
			print("run_until 0x%x -> 0x%x"%(pc, b_addr))
			pc = self.run_until(b_addr)

		if level_mode == True and oneThread == False:
			print("level_mode only support oneThread")
			self.interact()
			return ;

		if asmCode == False:
			level_mode = False

		if level_mode == False:
			start_level = 0

		if level_str is None:
			level_str = "  "

		if oneThread:
			thread_id, _ = self.get_thread_id()
			self.priv_globals["trace_thread_id"] = thread_id

		if logPattern == True:
			logPattern = "trace"

		if logPattern is not None and logPattern != False:
			suffix = ".log"
			if logPattern.endswith(".log"):
				suffix = ".log"
				logPattern = logPattern[:-4]
			elif logPattern.endswith(".txt"):
				suffix = ".txt"
				logPattern = logPattern[:-4]
		else:
			logPattern = None

		logfile_list = []

		end_status = False
		func_level = start_level
		split_str = "-"*0x20
		print("%s[trace start]%s"%(split_str, split_str))
		while True:
			try:
				info = "0x%x"%(pc-rec_base)
				if asmCode:
					info_items = self.get_disasm(pc, 1, False)
					[addr, asmInfo] = info_items[0]
					
					asm_prefix = ""
					if level_mode or function_mode:
						if level_mode:
							asm_prefix = level_str*func_level

						if asmInfo.startswith("call") or asmInfo.startswith("blx"):
							if level_mode:
								func_level += 1
						elif asmInfo.startswith("ret") or asmInfo.startswith("repz ret") or asmInfo.startswith("mov pc,"):
							if level_mode:
								func_level -= 1
								if func_level < 0:
									func_level = 0
						elif function_mode:
							info = ""
							asmInfo = ""
					if len(asmInfo) != 0:
						#print("func_level:", func_level)
						info = asm_prefix + info + ": " + asmInfo
					else:
						info = ""

				if logPattern is not None:
					if byThread == True:
						thread_id, _ = self.get_thread_id()
						logfile = logPattern + "_%d"%thread_id + suffix
					else:
						logfile = logPattern + suffix
				else:
					logfile = None

				if logfile is not None and appendMode == False:
					if logfile not in logfile_list:
						self.writefile(logfile, "")
						logfile_list.append(logfile)

				if len(info) != 0:
					if show:
						print(info)
					if logfile is not None:
						self.appendfile(logfile, info + "\n")

				if (e_addr is not None and pc == e_addr) or end_status == True:
					break

				last_addr = pc

				while True:
					pc = self.StepI()

					if oneThread:
						thread_id, _ = self.get_thread_id()
						if self.priv_globals["trace_thread_id"] != thread_id:
							self.chg_thread(self.priv_globals["trace_thread_id"])
							#print("1 last_pc:", hex(last_addr), "pc:", hex(pc))
							pc = self.get_reg("pc")
							#print("now_pc:", hex(pc))
							#self.interact()
							if pc == last_addr:
								continue
					break

				skip_sign = 0	
				if trace_handler is not None:
					sign = trace_handler(self, pc)
					#print("sign:", sign)
					if sign is not None:
						if sign == "end":
							end_status = True
							continue
						elif sign == "skip":
							skip_sign = 1

				if skip_sign == 0 and len(record_maps) > 0:
					if type(record_maps[0]) != list:
						record_maps = [record_maps]

					skip_sign = 2
					for items in record_maps:
						if pc >= items[0] and pc <= items[1]:
							skip_sign = 0
							break

				if skip_sign == 0 and len(skip_list) > 0:
					if pc in skip_list:
						skip_sign = 3

				if skip_sign > 0:
					next_addr = self.get_backtrace(2)[1]

					if function_mode == False:
						skip_chains = " [0x%x -> 0x%x -> 0x%x]"%(last_addr, pc, next_addr)
						info = level_str*func_level + "-- skip chains -> %s%s"%(self.skip_reason(skip_sign), skip_chains)
						if show:
							print(info)
						if logfile is not None:
							self.appendfile(logfile, info + "\n")	
					
					if level_mode:
						func_level -= 1
						if func_level < 0:
							func_level = 0
						
					if next_addr == -1:
						print("next_addr:", -1)
						self.interact()
						return ;
					pc = self.run_until(next_addr)
					if oneThread:
						thread_id, _ = self.get_thread_id()
						if self.priv_globals["trace_thread_id"] != thread_id:
							self.chg_thread(self.priv_globals["trace_thread_id"])
							#print("2 last_pc:", hex(last_addr), "pc:", hex(pc))
							pc = self.get_reg("pc")
							#print("now_pc:", hex(pc))
							#self.interact()

				if skip_loops == True and pc == last_addr:
					info_items = self.get_disasm(pc, 2, False)
					next_addr = info_items[1][0]
					pc = self.run_until(next_addr)

					if oneThread:
						thread_id, _ = self.get_thread_id()
						if self.priv_globals["trace_thread_id"] != thread_id:
							self.chg_thread(self.priv_globals["trace_thread_id"])
							#print("3 last_pc:", hex(last_addr), "pc:", hex(pc))
							pc = self.get_reg("pc")
							#print("now_pc:", hex(pc))
							#self.interact()

					if pc == last_addr:
						self.interact()
						return ;
					continue	

			except Exception as ex:
				print('[+] ' + repr(ex))
				#self.interrupt_process()
				self.interact()
				break
		print("%s[trace end]%s"%(split_str, split_str))


	def get_target(self):
		return self.target_argv

	def wait_interact(self):
		import signal

		print("<wait for interact> (/continue/exit/quit/c/e/q/ctrl+c)")
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

	def interact_raw(self):
		if io_wrapper == "pwntools":
			self.io.interactive()
		else:
			self.io.interact()

	def gdb_interact(self, break_list = [], gdbscript_pre = "", gdbscript_suf = "", init_file = ".self.init", terminal = None, sudo = True):
		pc = self.get_reg("pc")
		#halt_code = self._asm_("jmp 0x%x"%pc, pc)
		halt_code = self._asm_("jmp $", pc)
		restore_value = self.read_long(pc)
		self.write_mem(pc, halt_code)
		target = self.get_target()

		init_script = ""
		if gdbscript_pre != "":
			init_script += gdbscript_pre.strip() + "\n"
		init_script += target + "\n"
		init_script += "set *(unsigned long long *)0x%x=0x%x\n"%(pc, restore_value)
		init_script += "context\n"
		init_script += "\n".join(["b *0x%x"%c for c in break_list]) + "\n"
		init_script += gdbscript_suf.strip()
		init_file = os.path.realpath(init_file)
		self.writefile(init_file, init_script)

		self.detach()

		cmdline = ""
		if sudo == True:
			cmdline += "sudo "
		cmdline += "%s -x %s"%(self.gdb_path, init_file)
		self.run_in_new_terminal(cmdline, terminal = terminal)
		self.wait_interact()
		return

	def setvbuf0(self, stdin = None, stdout = None, stderr = None):
		self.save_context()

		if stdin is None:
			stdin = self.get_symbol_value("stdin")
			if stdin != 0:
				stdin = self.get_lib_symbol("stdin")
				stdin = self.read_pointer(stdin)
		if stdout is None:
			stdout = self.get_symbol_value("stdout")
			if stdout != 0:
				stdout = self.get_lib_symbol("stdout")
				stdout = self.read_pointer(stdout)
		if stderr is None:
			stderr = self.get_symbol_value("stderr")
			if stderr != 0:
				stderr = self.get_lib_symbol("stderr")
				stderr = self.read_pointer(stderr)

		#setvbuf = pygdb.get_symbol_value("setvbuf")
		#pygdb.set_bp(setvbuf)
		self.call("setvbuf", [stdin, 0, 2, 0])#, debug_list = True)
		self.call("setvbuf", [stdout, 0, 2, 0])
		self.call("setvbuf", [stderr, 0, 2, 0])
		self.restore_context()

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
		last_addr = old_addr
		while addr - old_addr < 0x10000:
			#content = self.execute("x/40i 0x%x"%addr)
			asmInfos = self.get_disasm(addr, 40)
			for asm_item in asmInfos:
				if len(asm_item) < 2:
					break
				cur_addr = asm_item[0]
				opcode = asm_item[1]
				if opcode.startswith("ret") or opcode.startswith("repz ret"):
					return cur_addr
				addr = cur_addr
			if addr == last_addr:
				break
			last_addr = addr

	def invoke_s(self, func, *args, **kwrds):
		self.save_context()
		result = func(*args, **kwrds)
		self.restore_context()
		return result

	def invoke_t(self, func, *args, **kwrds):
		self.thread_lock()
		result = func(*args, **kwrds)
		self.thread_unlock()
		return result

	def invoke_st(self, func, *args, **kwrds):
		self.save_context()

		#print("lock status")
		#print(self.show_scheduler())
		self.thread_lock()
		#print(self.show_scheduler())
		result = func(*args, **kwrds)

		#print("unlock status")
		#print(self.show_scheduler())
		self.thread_unlock()
		#print(self.show_scheduler())
		self.restore_context()
		return result

	def __getattr__(self, key):
		#print "__getattr__", key
		if key in self.__dict__:
			return self.__dict__[key]

		if key in PyGDB.__dict__:
			return PyGDB.__dict__[key]

		if key.endswith("_s"):
			real_key = key[:-2]
			if real_key in PyGDB.__dict__:
				#print "real_key in"
				def wrap(*args, **kwrds):
					func = getattr(PyGDB, real_key)
					args = [self] + list(args)
					return self.invoke_s(func, *args, **kwrds)
				return wrap

		elif key.endswith("_t"):
			real_key = key[:-2]
			if real_key in PyGDB.__dict__:
				#print "real_key in"
				def wrap(*args, **kwrds):
					func = getattr(PyGDB, real_key)
					args = [self] + list(args)
					return self.invoke_t(func, *args, **kwrds)
				return wrap

		elif key[-3:] in ["_ts", "_st"]:
			real_key = key[:-3]
			if real_key in PyGDB.__dict__:
				#print "real_key in"
				def wrap(*args, **kwrds):
					func = getattr(PyGDB, real_key)
					args = [self] + list(args)
					return self.invoke_st(func, *args, **kwrds)
				return wrap
		raise AttributeError("'module' object has no attribute '%s'" % key)

	def make_tiny_elf(self, shellocde, outfile = None, base = None, mode = 32):
		elf_bin = PyGDB_make_tiny_elf(shellocde, outfile, base, mode)
		return elf_bin

	def remove_pairs(self, line, pairs = ["<", ">"]):
		while True:
			pos_b = line.find(pairs[0], 0)
			if pos_b == -1:
				break
			pos_e = line.find(pairs[1], pos_b + 1)
			if pos_e == -1:
				break
			line = line[:pos_b] + line[pos_e+1:]
		return line

	def remvoe_inject_patch(self, addr):
		if addr in self.inject_patch_map.keys():
			[target_data, origin_data] = self.inject_patch_map[addr]
			self.write_mem(addr, origin_data)
			self.inject_patch_map.pop(addr)
			#self.inject_hook_free(addr, len(target_data))
			return len(origin_data)
		return 0

	def inject_restore(self, addr):
		if addr in self.inject_hook_map.keys():
			self.remove_inject_hook(addr)
		elif addr in self.inject_patch_map.keys():
			self.remvoe_inject_patch(addr)
			"""
			[_, origin_data] = self.inject_patch_map[addr]
			self.write_mem(addr, origin_data)
			self.inject_patch_map.pop(addr)
			"""
			
	def inject_patch_data(self, addr, data):
		self.inject_restore(addr)

		origin_data = self.read_mem(addr, len(data))
		self.write_mem(addr, data)
		self.inject_patch_map[addr] = [data, origin_data]

	def inject_patch_asm(self, addr, asm_code, show = False):
		self.inject_restore(addr)

		new_asm_code_list = []
		for line in asm_code.strip().split("\n"):
			line = line.strip()
			if line.startswith(";") or line.startswith("//"):
				continue
			line = self.remove_pairs(line, ["<", ">"])
			
			new_asm_code_list.append(line)
			line_strip = line.replace("\t", " ").strip()
			if line_strip.startswith("call "):
				name = line_strip.replace("call ", "").strip()
				if name.startswith("0x") or name.isdigit():
					continue
				else:
					if name in self.inject_hook_globals.keys():
						name_addr = self.inject_hook_globals[name]
					else:
						name_addr = self.get_symbol_value(name)
					line = "call 0x%x"%name_addr
					new_asm_code_list[-1] = line
		#new_asm_code = "\n".join(new_asm_code_list)

		new_asm_code = "\n".join(new_asm_code_list)

		target_code = self._asm_(new_asm_code, addr)

		end_addr = 0
		origin_code_list = []
		cur_addr = addr
		while True:
			asmInfos = self.get_disasm(cur_addr, 2, parse = False)
			if len(asmInfos) < 2:
				break
			asmInfo = asmInfos[0]
			[asm_addr, asm_code] = asmInfo
			asm_code = self.remove_pairs(asm_code, ["<", ">"])
			if show:
				print(hex(asm_addr), ":", asm_code)
			if asm_addr - addr >= len(target_code):
				end_addr = asm_addr
				break
			cur_addr = asmInfos[1][0]

		if end_addr != 0:
			use_size = end_addr - addr
			origin_data = self.read_mem(addr, use_size)
			#intel mode
			target_code = target_code.ljust(use_size, self.nop_code)
			self.write_mem(addr, target_code)
			self.inject_patch_map[addr] = [target_code, origin_data]
		else:
			print("inject hook error")
			return

	def core_inject_init(self, show = False):
		if self.inject_hook_base == 0:
			self.auto_config_inject()

		if "pygdb_dispatch_addr" in self.core_pygdb_maps.keys():
			return 

		pygdb_so_file = os.path.join(self.pygdb_libpath, "libpygdb.so")
		
		func_list =  ["core_hook_dispatcher"]#, "hexdump", "setvbuf0"]
		plt_maps, lib_base = self.load_lib_plt(pygdb_so_file, func_list = func_list, config = False)
		
		self.core_pygdb_maps = plt_maps

		func_list = ["pygdb_handler_array", "pygdb_handler_size", "pygdb_handler_pos"]
		pygdb_so_lib = ELF(pygdb_so_file)
		pygdb_so_lib.address = lib_base


		for key in func_list:
			self.core_pygdb_maps[key] = pygdb_so_lib.symbols[key]

		#print("plt_maps:")
		#for key in plt_maps.keys():
		#	print(key, hex(plt_maps[key]))

		base_addr = 0x8000000

		addr = call_dispatcher_addr = self.inject_hook_addr
		ctx  = True

		new_code_addr = self.inject_hook_addr - call_dispatcher_addr + base_addr
		if ctx == True:
			new_code_addr += len(self._asm_(self.core_push_context_asm(call_dispatcher_addr)))
		
		self.write_int(self.core_pygdb_maps["pygdb_handler_pos"], 0x0)


		call_dispatcher_asm_list = []
		"""
		call_dispatcher_asm_list.append("%s %s, 0x%x"%(self.mov_asm, self.common_reg, self.core_pygdb_maps["core_hook_dispatcher"]))
		call_dispatcher_asm_list.append("call %s"%self.common_reg)
		"""
		# begins
		call_dispatcher_asm_list = []
		if True:
			args_new = [self.sp_reg] + []
			if self.is_arm():
				for i in range(len(args_new)):
					call_dispatcher_asm_list.append("mov %s, %s"%(self.arch_args[i], args_new[i]))
			else:
				if self.bits == 32:
					for i in range(len(args_new)-1, -1, -1):
						call_dispatcher_asm_list.append("%s %s"%(self.push_asm, args_new[i]))
				else:
					for i in range(len(args_new)):
						call_dispatcher_asm_list.append("mov %s, %s"%(self.arch_args[i], args_new[i]))

		func_addr = self.core_pygdb_maps["core_hook_dispatcher"]
		if self.is_arm():
			call_dispatcher_asm_list.append("%s r1, 0x%x"%(self.mov_asm, func_addr))
			call_dispatcher_asm_list.append("blx r1")
		else:
			call_dispatcher_asm_list.append("%s %s, 0x%x"%(self.mov_asm, self.common_reg, func_addr))
			call_dispatcher_asm_list.append("call %s"%self.common_reg)

		if self.is_arm() == False and self.bits == 32:
			for i in range(len(args_new)-1, -1, -1):
				call_dispatcher_asm_list.append("%s %s"%(self.pop_asm, self,common_reg))
		# ends

		call_dispatcher_asm  = "\n".join(call_dispatcher_asm_list)
		call_dispatcher_code = self._asm_(call_dispatcher_asm, new_code_addr)

		origin_code_list = []

		if True:

			if ctx == True:
				new_asm_code_list = [self.core_push_context_asm(addr)] + call_dispatcher_asm_list + [self.core_pop_context_asm()]
			else:
				new_asm_code_list = call_dispatcher_asm_list

			new_asm_code = "\n".join(new_asm_code_list)
			if show:
				print("total code:")
				print("-"*0x10)
				print(new_asm_code)
				print("-"*0x10)

			#print("new_asm_code:")
			#print(new_asm_code)
			patch_code = self._asm_(new_asm_code, self.inject_hook_addr - addr + base_addr)
			#print("new_asm_code ok:")

			patch_addr = self.inject_hook_alloc(patch_code)
			if patch_addr != 0:				
				if show:
					print("total dispatcher_code:", hex(addr))
					print("-"*0x10)
					print(self.get_code(patch_addr, 0x10, below = True))
					print("-"*0x10)
			self.core_pygdb_maps["pygdb_dispatch_addr"] = patch_addr
		else:
			print("inject hook error")
			return 0

		return patch_addr


	def core_push_context_asm(self, pc = None):

		asm_code_list = []
		#pc in stack when use call
		asm_code_list.append("%s %s"%(self.push_asm, self.sp_reg))
		#align
		if self.is_arm() == True:
			aligin_val = 0
		else:
			aligin_val = 1
		if len(self.context_regs) % 2 != aligin_val:
			asm_code_list.append("%s %s"%(self.push_asm, self.common_reg))
		if self.is_arm() == False:
			asm_code_list.append("pushf")
		for idx in range(len(self.context_regs) - 1, -1, -1):
			reg = self.context_regs[idx]
			if reg in [self.pc_reg, self.sp_reg]:
				continue
			asm_code_list.append("%s %s"%(self.push_asm, reg))
		#asm_code_list.append("pushf")
		return "\n".join(asm_code_list)

	def core_pop_context_asm(self):

		asm_code_list = []
		#asm_code_list.append("popfs")
		for idx in range(len(self.context_regs)):
			reg = self.context_regs[idx]
			if reg in [self.sp_reg, self.pc_reg]:
				continue
			asm_code_list.append("%s %s"%(self.pop_asm, reg))
		if self.is_arm() == False:
			asm_code_list.append("popf")
		#align
		if self.is_arm() == True:
			aligin_val = 0
		else:
			aligin_val = 1
		if len(self.context_regs) % 2 != aligin_val:
			asm_code_list.append("%s %s"%(self.pop_asm, self.common_reg))
		asm_code_list.append("%s %s"%(self.pop_asm, self.sp_reg))
		asm_code_list.append("ret")
		return "\n".join(asm_code_list)

	def core_set_handler_item(self, idx, hook_addr, handler, ret_addr):
		pygdb_handler_pos   = self.core_pygdb_maps["pygdb_handler_pos"]
		pygdb_handler_size  = self.core_pygdb_maps["pygdb_handler_size"]
		pygdb_handler_array = self.core_pygdb_maps["pygdb_handler_array"]

		addr_size = self.bits / 8
		#print("write 0x%x: 0x%x, 0x%x, 0x%x"%(pygdb_handler_array + (idx*3 + 0)*addr_size, hook_addr, handler, ret_addr))
		self.write_pointer(pygdb_handler_array + (idx*3 + 0)*addr_size, hook_addr)
		self.write_pointer(pygdb_handler_array + (idx*3 + 1)*addr_size, handler)
		self.write_pointer(pygdb_handler_array + (idx*3 + 2)*addr_size, ret_addr)


	def core_inject_hook_func(self, addr, func, libname = "libc", show = False):
		if len(self.core_pygdb_maps.keys()) == 0:
			self.core_inject_init(show = show)
		self.auto_config_inject(addr)

		if addr in self.inject_hook_map.keys():
			self.remove_inject_hook(addr)

		if type(func) == str:
			if func in self.inject_hook_globals.keys():
				func_addr = self.inject_hook_globals[func]
			else:
				func_addr = self.get_symbol_value(func)
				if func_addr == 0:
					func_addr = self.get_lib_func(func, libname = libname)
		else:
			func_addr = func

		plt_key = "dispatcher_plt_%x"%(self.inject_hook_base)
		if plt_key not in self.core_pygdb_maps.keys():
			sym_count = 1
			addr_size = self.bits / 8
			plt_base = self.inject_hook_alloc(sym_count*8, align = True)
			got_base = self.inject_hook_alloc(sym_count*addr_size, align = True)
			self.write_plt_got(self.core_pygdb_maps["pygdb_dispatch_addr"], plt_base, got_base)
			pygdb_dispatch_plt = plt_base
		else:
			pygdb_dispatch_plt = self.core_pygdb_maps[plt_key]


		if plt_base == 0 or got_base == 0:
			print("plt got alloc error")
			return 

		#print("func:", func)
		#print("func_addr:", hex(func_addr))

		pygdb_handler_pos   = self.core_pygdb_maps["pygdb_handler_pos"]
		pygdb_handler_size  = self.core_pygdb_maps["pygdb_handler_size"]
		pygdb_handler_array = self.core_pygdb_maps["pygdb_handler_array"]

		cur_pos = self.read_int(pygdb_handler_pos)
		size = self.read_int(pygdb_handler_size)

		if cur_pos >= size:
			print("hook array is full")
			return 

		base_addr = 0x8000000

		jmp_target_asm 	= "call 0x%x"%(self.inject_hook_addr - addr + base_addr)
		jmp_target_code = self._asm_(jmp_target_asm, addr - addr + base_addr)

		code_header_asm = "jmp 0x%x"%(pygdb_dispatch_plt - addr + base_addr)
			
		asmInfos = self.get_disasm(addr, 0x40, parse = False, base = base_addr)
		end_addr = 0
		origin_code_list = []
		for idx in range(len(asmInfos)):
			asmInfo = asmInfos[idx]
			[asm_addr, asm_code] = asmInfo
			asm_code = self.remove_pairs(asm_code, ["<", ">"])
			#print(hex(asm_addr), ":", asm_code)
			if asm_addr - base_addr >= len(jmp_target_code):
				end_addr = asm_addr
				break
			origin_code_list.append(asm_code)

		if end_addr != 0:
			origin_data = self.read_mem(addr, len(jmp_target_code))

			jmp_back_asm = "jmp 0x%x"%(end_addr)
			new_asm_code_list = [code_header_asm] + origin_code_list + [jmp_back_asm]
			new_asm_code = "\n".join(new_asm_code_list)
			if show:
				print("inject code:")
				print("-"*0x10)
				print(new_asm_code)
				print("-"*0x10)

			#print("new_asm_code:")
			#print(new_asm_code)
			patch_code = self._asm_(new_asm_code, self.inject_hook_addr - addr + base_addr)
			patch_code_header = self._asm_(code_header_asm, self.inject_hook_addr - addr + base_addr)
			#print("new_asm_code ok:")

			patch_addr = self.inject_hook_alloc(patch_code)
			if patch_addr != 0:

				if show:
					print("origin:", hex(addr))
					print("-"*0x10)
					print(self.get_code(addr, 0x5, below = True))
					print("-"*0x10)
				self.write_mem(addr, jmp_target_code)
				hook_item = [patch_addr, patch_code, addr, origin_data, cur_pos]
				
				if show:
					print("after:", hex(addr))
					print("-"*0x10)
					print(self.get_code(addr, 0x5, below = True))
					print("-"*0x10)

					print("patch_addr:", hex(patch_addr))
					print("-"*0x10)
					print(self.get_code(patch_addr, 0x10, below = True))
					print("-"*0x10)

				self.core_set_handler_item(cur_pos, addr, func_addr, patch_addr + len(patch_code_header))
				self.write_int(pygdb_handler_pos, cur_pos + 1)

				self.inject_hook_map[addr] = hook_item
				self.inject_patch_map[addr] = [jmp_target_code, origin_data]
		else:
			print("inject hook error")
			return 0

		return patch_addr

	def push_context_asm(self, pc = None):

		asm_code_list = []

		asm_code_list.append("%s %s"%(self.push_asm, self.sp_reg))
		asm_code_list.append("%s %s"%(self.push_asm, self.common_reg))
		#align
		if self.is_arm() == True:
			aligin_val = 0
		else:
			aligin_val = 1
		if len(self.context_regs) % 2 != aligin_val:
			asm_code_list.append("%s %s"%(self.push_asm, self.common_reg))
		if self.is_arm() == False:
			asm_code_list.append("pushf")
		for idx in range(len(self.context_regs) - 1, -1, -1):
			reg = self.context_regs[idx]
			if reg == self.pc_reg:
				if pc is not None:
					asm_code_list.append("%s %s, 0x%x"%(self.mov_asm, self.common_reg, pc))
					asm_code_list.append("%s %s"%(self.push_asm, self.common_reg))
					continue
			elif reg in [self.sp_reg, self.common_reg]:
				continue
			asm_code_list.append("%s %s"%(self.push_asm, reg))
		#asm_code_list.append("pushf")
		return "\n".join(asm_code_list)

	def pop_context_asm(self):

		asm_code_list = []
		#asm_code_list.append("popfs")
		for idx in range(len(self.context_regs)):
			reg = self.context_regs[idx]
			if reg == self.pc_reg:
				asm_code_list.append("add %s, 0x%d"%(self.sp_reg, self.bits/8))
				continue
			elif reg in [self.sp_reg, self.common_reg]:
				continue
			asm_code_list.append("%s %s"%(self.pop_asm, reg))
		if self.is_arm() == False:
			asm_code_list.append("popf")
		asm_code_list.append("%s %s"%(self.pop_asm, self.common_reg))
		#align
		if self.is_arm() == True:
			aligin_val = 0
		else:
			aligin_val = 1
		if len(self.context_regs) % 2 != aligin_val:
			asm_code_list.append("%s %s"%(self.pop_asm, self.common_reg))
		asm_code_list.append("%s %s"%(self.pop_asm, self.sp_reg))
		return "\n".join(asm_code_list)

	def inject_hook_func(self, addr, func, libname = "libc", args = [], show = False):
		return self.core_inject_hook_func(addr, func = func, libname = libname, show = show)

	def inject_hook(self, addr, asm_code_func, hook_type = "func", ctx = True, show = False):
		if hook_type == "asm":
			return self.inject_hook_asm(addr, asm_code_func, ctx = ctx, show = show)
		else:
			return self.core_inject_hook_func(addr, asm_code_func, show = show)

	def inject_hook_code(self, addr, code, ctx = True, show = False):
		self.auto_config_inject(addr)

		"""
		self.inject_hook_map = {}
		self.inject_hook_addr = 0x0
		self.inject_hook_base = 0x0
		self.inject_hook_size = 0x0
		self.inject_patch_map = {}
		self.inject_free_map  = {}
		self.inject_hook_globals = {}
		"""
		base_addr = 0x8000000
		if addr in self.inject_hook_map.keys():
			self.remove_inject_hook(addr)
		new_code_addr = self.inject_hook_addr - addr + base_addr
		if ctx == True:
			new_code_addr += len(self._asm_(self.push_context_asm(addr)))
		asm_code = self._disasm_(code, vma = new_code_addr)
		asmInfos = self.parse_disasm(asm_code, mode = 2)

		new_asm_code_list = []
		for asmInfo in asmInfos:
			new_asm_code_list.append(asmInfo[1])

		jmp_target_asm 	= "jmp 0x%x"%(self.inject_hook_addr - addr + base_addr)
		jmp_target_code = self._asm_(jmp_target_asm, addr - addr + base_addr)

		asmInfos = self.get_disasm(addr, 0x40, parse = False, base = base_addr)
		end_addr = 0
		origin_code_list = []
		for idx in range(len(asmInfos)):
			asmInfo = asmInfos[idx]
			[asm_addr, asm_code] = asmInfo
			asm_code = self.remove_pairs(asm_code, ["<", ">"])
			#print(hex(asm_addr), ":", asm_code)
			if asm_addr - base_addr >= len(jmp_target_code):
				end_addr = asm_addr
				break
			origin_code_list.append(asm_code)

		if end_addr != 0:
			origin_data = self.read_mem(addr, len(jmp_target_code))

			jmp_back_asm = "jmp 0x%x"%(end_addr)

			if ctx == True:
				new_asm_code_list = [self.push_context_asm(addr)] + new_asm_code_list + [self.pop_context_asm()]
			new_asm_code_list = new_asm_code_list + origin_code_list + [jmp_back_asm]
			new_asm_code = "\n".join(new_asm_code_list)
			if show:
				print("inject code:")
				print("-"*0x10)
				print(new_asm_code)
				print("-"*0x10)

			#print("new_asm_code:")
			#print(new_asm_code)
			patch_code = self._asm_(new_asm_code, self.inject_hook_addr - addr + base_addr)
			#print("new_asm_code ok:")

			patch_addr = self.inject_hook_alloc(patch_code)
			if patch_addr != 0:

				if show:
					print("origin:", hex(addr))
					print("-"*0x10)
					print(self.get_code(addr, 0x5, below = True))
					print("-"*0x10)
				self.write_mem(addr, jmp_target_code)
				hook_item = [patch_addr, patch_code, addr, origin_data, -1]
				
				if show:
					print("after:", hex(addr))
					print("-"*0x10)
					print(self.get_code(addr, 0x5, below = True))
					print("-"*0x10)
					end_addr = end_addr + addr - base_addr
					print("jmp_back_addr:", hex(end_addr))
					print("-"*0x10)
					print(self.get_code(end_addr, 0x5, below = True))
					print("-"*0x10)

					print("patch_addr:", hex(patch_addr))
					print("-"*0x10)
					print(self.get_code(patch_addr, 0x10, below = True))
					print("-"*0x10)
				self.inject_hook_map[addr] = hook_item
				self.inject_patch_map[addr] = [jmp_target_code, origin_data]
		else:
			print("inject hook error")
			return 0

		return patch_addr

	def inject_hook_asm(self, addr, asm_code, ctx = True, show = False):
		self.auto_config_inject(addr)
		"""
		self.inject_hook_map = {}
		self.inject_hook_addr = 0x0
		self.inject_hook_base = 0x0
		self.inject_hook_size = 0x0
		self.inject_patch_map = {}
		self.inject_free_map  = {}
		self.inject_hook_globals = {}
		"""
		if addr in self.inject_hook_map.keys():
			self.remove_inject_hook(addr)

		new_asm_code_list = []
		for line in asm_code.strip().split("\n"):
			line = line.strip()
			if line.startswith(";") or line.startswith("//"):
				continue
			line = self.remove_pairs(line, ["<", ">"])
			
			new_asm_code_list.append(line)
			line_strip = line.replace("\t", " ").strip()
			if line_strip.startswith("call "):
				name = line_strip.replace("call ", "").strip()
				if name.startswith("0x") or name.isdigit():
					continue
				else:
					if name in self.inject_hook_globals.keys():
						name_addr = self.inject_hook_globals[name]
					else:
						name_addr = self.get_symbol_value(name)
					line = "call 0x%x"%name_addr
					new_asm_code_list[-1] = line
			elif line_strip.startswith("mov "):
				name = line_strip.split(",")[-1].strip()
				if name.startswith("0x") or name.isdigit():
					continue
				else:
					if name in self.inject_hook_globals.keys():
						name_addr = self.inject_hook_globals[name]
						line = line.replace(name, "0x%x"%name_addr)
						new_asm_code_list[-1] = line
		#new_asm_code = "\n".join(new_asm_code_list)

		target_offset = 0
		if ctx == True:
			code_pre = self._asm_(self.push_context_asm(addr))
			target_offset = len(code_pre)

		inject_code = self._asm_("\n".join(new_asm_code_list), self.inject_hook_addr + target_offset)

		return self.inject_hook_code(addr, inject_code, ctx = ctx, show = show)

	def remove_inject_hook(self, addr):
		if addr in self.inject_hook_map.keys():
			hook_item = self.inject_hook_map[addr]
			[patch_addr, patch_code, origin_addr, origin_data, cur_pos] = hook_item
			self.inject_hook_free(patch_addr, len(patch_code))
			self.inject_hook_map.pop(addr)
			#self.inject_patch_map.pop(addr)
			#self.write_mem(addr, origin_data)
			self.remvoe_inject_patch(addr)

			if cur_pos != -1:
				self.core_set_handler_item(cur_pos, 0, 0, 0)


	def clear_inject_hook(self):
		for key in self.inject_hook_map.keys():
			self.remove_inject_hook(key)

	def clear_inject_patch(self):
		self.clear_inject_hook()
		for key in self.inject_patch_map.keys():
			self.inject_hook_free(key)
			self.remvoe_inject_patch(key)

	def inject_hook_alloc(self, data_size, align = None):
		if self.inject_hook_base == 0:
			self.auto_config_inject()

		if type(data_size) in [str, bytes]:
			data = data_size
			size = len(data)
		else:
			size = data_size
			data = ''

		#print("align0:", align)
		if align == True:
			align = (self.bits / 8) * 2
		#print("align1:", align)

		align_addr = 0
		if align is not None and (self.inject_hook_addr % align) != 0:
			empty_size = align - (self.inject_hook_addr % align)
			align_addr = align_addr = self.inject_hook_alloc(empty_size)
			#print("empty_size:", hex(empty_size))
			#print("align_addr:", hex(align_addr))
			if align_addr == 0:
				return 0

		if self.inject_hook_size >= size:
			addr = self.inject_hook_addr
			origin_data = self.read_mem(self.inject_hook_addr, size)
			if len(data) > 0:
				self.write_mem(self.inject_hook_addr, data)
			self.inject_hook_addr += size
			self.inject_hook_size -= size
			self.inject_patch_map[addr] = [data, origin_data]
		else:
			print("inject area is not enough")
			addr = 0

		if align_addr != 0:
			self.inject_hook_free(align_addr)			
		return addr

	def inject_consolidate(self):
		last_count = len(self.inject_free_map.keys())
		while last_count > 0:
			for key in self.inject_free_map.keys():
				size = self.inject_free_map[key]
				self.inject_hook_free(key, size)
			count = len(self.inject_free_map.keys())
			if count == last_count:
				break
			last_count = count

	def inject_hook_free(self, addr, size = None):
		#print("	  free in:", hex(addr), hex(size))
		if addr in self.inject_patch_map.keys():
			#self.inject_patch_map.pop(addr)
			use_size = self.remvoe_inject_patch(addr)
			if size is None or size != use_size:
				size = use_size

		if size is None:
			#print("error size")
			return

		#print("	  free on:", hex(addr), hex(size))
		if addr < self.inject_hook_addr and addr + size == self.inject_hook_addr:
			self.inject_hook_size += self.inject_hook_addr - addr
			self.inject_hook_addr = addr
			
			if addr not in self.inject_free_map.keys():
				self.inject_consolidate()
			else:
				#print("pop here1")
				self.inject_free_map.pop(addr)
		else:
			if addr >= self.inject_hook_addr:
				#print("dup free", hex(addr))
				return
			if addr not in self.inject_free_map.keys():
				self.inject_free_map[addr] = size
				#print(self.inject_free_map)
				self.inject_consolidate()
				#print(self.inject_free_map)
			elif addr < self.inject_hook_base or addr > self.inject_hook_addr + self.inject_hook_size:
				#print("pop here2")
				self.inject_free_map.pop(addr)

	def switch_inject_context(self, base):
		if self.inject_hook_base == base:
			return 
		if base in self.inject_hook_context.keys():
			if self.inject_hook_base != 0x0:
				hook_item = self.inject_hook_context[self.inject_hook_base]
				hook_item[0] = self.inject_hook_addr
				hook_item[1] = self.inject_hook_size
				hook_item[2] = self.inject_free_map
				hook_item[3] = self.inject_patch_map
				hook_item[4] = self.inject_hook_map

			print("switch_inject_context", "from", hex(self.inject_hook_base), "to", hex(base))
			
			self.inject_hook_base = base
			hook_item = self.inject_hook_context[self.inject_hook_base]
			self.inject_hook_addr = hook_item[0]
			self.inject_hook_size = hook_item[1]
			self.inject_free_map  = hook_item[2]
			self.inject_patch_map = hook_item[3]
			self.inject_hook_map  = hook_item[4]

	def config_inject_map(self, base = None, size = 0x2000, globals_map = None):
		if base is not None:
			if base not in self.inject_hook_context.keys():
				self.inject_hook_context[base] = [base, size, {}, {}, {}]
			self.switch_inject_context(base)
		if globals_map is not None:
			for key in globals_map.keys():
				self.inject_hook_globals[key] = globals_map[key]

	def auto_config_inject(self, addr = None, size = 0x2000, flag = "rwx"):
		if self.inject_hook_auto == False:
			return

		if addr is None:
			addr = self.codebase()

		addr = addr & 0xfffffffffffff000

		if len(self.inject_hook_context.keys()) > 0:
			if abs(self.inject_hook_base - addr) < 0x4000000:
				return self.inject_hook_base
			if addr in self.inject_hook_context.keys():
				self.switch_inject_context(addr)
				return addr
			else:
				for key in self.inject_hook_context.keys():
					if abs(key - addr) < 0x4000000:
						self.switch_inject_context(key)
						return key

		cur_addr = addr + 0x600000
		try_times = 100
		for i in range(try_times):
			res = self.mmap(cur_addr, size, flag)
			if res != 0:
				break
			cur_addr += 0x10000
		if res != 0:
			self.config_inject_map(res, size)
		return res

	def inject_into_file(self, infile, outfile = None, base = 0):
		file_data = self.readfile(infile)
		for addr in self.inject_patch_map.keys():
			#print(addr)
			[data, _] = self.inject_patch_map[addr]
			file_data = self.patch_data(file_data, addr - base, data)

		if outfile is None:
			outfile = infile
		self.writefile(outfile, file_data)
		self.run_cmd("chmod +x %s"%outfile)

	def show_inject_info(self):
		print("inject_hook_map:")
		for key in self.inject_hook_map.keys():
			hook_item = self.inject_hook_map[key]
			[patch_addr, patch_code, origin_addr, origin_data, idx] = hook_item
			print(hex(key), ":", hex(patch_addr), hex(len(patch_code)), hex(origin_addr), hex(len(origin_data)), idx)

		print("inject_patch_map:")
		for key in self.inject_patch_map.keys():	
			patch_item = self.inject_patch_map[key]
			[patch_data, origin_data] = patch_item
			print(hex(key), ":", hex(len(patch_data)), hex(len(origin_data)))

		print("inject_free_map:")
		for key in self.inject_free_map.keys():	
			size = self.inject_free_map[key]
			print(hex(key), ":", hex(size))

		print("inject_hook_base:", hex(self.inject_hook_base))
		print("inject_hook_size:", hex(self.inject_hook_size))
		print("inject_hook_addr:", hex(self.inject_hook_addr))


	def parse_sock_info(self, sockaddr):
		info = ""
		family = self.read_word(sockaddr)
		port = self.read_word(sockaddr + 2, "big")
		if family == socket.AF_INET:
			ip_data = self.read_mem(sockaddr + 4, 4)
			ip = self.parse_ip4(ip_data)
			info = "%s:%d"%(ip, port)
		elif family == socket.AF_INET6:
			sp = self.get_reg("sp")
			stackSize = 0x40
			sp -= stackSize
			self.set_reg("sp", sp)

			ipAddr = sp
			self.call("inet_ntop", [socket.AF_INET6, sockaddr + 8, ipAddr, 0x20])
			ip = self.readString(ipAddr)
			info = "[%s]:%d"%(ip, port)

			sp += stackSize
			self.set_reg("sp", sp)
		return info

	def get_sock_info(self, sock):
		pc = self.get_reg("pc")
		sp = self.get_reg("sp")
		stackSize = 0x40
		sp -= stackSize

		self.set_reg("sp", sp)

		sockaddr = sp
		lenAddr = sp + 0x30
		info_list = []

		self.write_int(lenAddr, 0x20)
		res = self.call("getsockname", [sock, sockaddr, lenAddr])#, debug_list = ["getsockname"])
		#self.hexdump(sockaddr, 0x20)
		if res == 0:
			info = self.parse_sock_info(sockaddr)
			info_list.append(info)

		self.write_int(lenAddr, 0x20)
		res = self.call("getpeername", [sock, sockaddr, lenAddr], debug_list = [])
		#self.hexdump(sockaddr, 0x20)
		if res == 0:
			info = self.parse_sock_info(sockaddr)
			info_list.append(info)

		info = " <=> ".join(info_list)

		sp += stackSize
		self.set_reg("sp", sp)

		return info

	def get_file_info(self, fd):
		sp = self.get_reg("sp")
		stackSize = 0x100
		sp -= stackSize
		self.set_reg("sp", sp)

		fd_path = "/proc/self/fd/%d"%fd
		obj_file = sp
		self.write_mem(obj_file, '\x00')
		res = self.call("readlink", [fd_path, obj_file, 0x100])#, debug_list = ["readlink"])
		if res < 0:
			info = ""
		else:
			info = self.read_mem(obj_file, res)
		sp += stackSize
		self.set_reg("sp", sp)

		return info

	def get_fd_info(self, fd):
		info = self.get_file_info(fd)
		if info.startswith("socket:") or info == "":
			pc = self.get_reg("pc")
			#print("pc before call get_sock_info:", hex(pc))
			new_info = self.get_sock_info(fd)
			if new_info != "":
				info = new_info
		return info