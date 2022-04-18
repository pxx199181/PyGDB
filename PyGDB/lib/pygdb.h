#ifndef PYGDB_H
#define PYGDB_H

#define ARCH_MODE_X64
//#define ARCH_MODE_X32
//#define ARCH_MODE_ARM
//#define ARCH_MODE_AARCH64

#ifdef ARCH_MODE_X64
typedef struct _context {
	long int rax;
	long int rbx;
	long int rcx;
	long int rdx;
	long int rsi;
	long int rdi;
	long int rbp;
	long int r8;
	long int r9;
	long int r11;
	long int r12;
	long int r13;
	long int r14;
	long int r15;
	long int eflags;
	long int reserved;
	long int rsp;
	long int rip;
} context;
#endif

void core_hexdump(unsigned char *data, int size, char *banner);
void core_setvbuf0();
void core_log(int fd, char *data);
void core_logf(int fd, char *data, long int val);
void core_dup_io(char *ip, int port, int *fd_list, int fd_count);

#endif 
//PYGDB_H
