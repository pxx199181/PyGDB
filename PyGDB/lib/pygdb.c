#include <stdio.h>

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

void hexdump(unsigned char *data, int size, char *banner)
{
	if (banner != NULL) {
		printf("%s\n", banner);
	}
	char ascii_letter[0x20] = {0};
	int i;
	for (i = 0; i < size; i++) {
		if (i % 0x10 == 0) {
			printf("%p:  ", &data[i]);
		}
		printf("%02x ", data[i]);
		if (data[i] >= 0x20 && data[i] < 0x7f)
			ascii_letter[i%0x10] = data[i];
		else
			ascii_letter[i%0x10] = '.';
		if (i % 0x10 == 0xf) {
			printf("%s\n", ascii_letter);
		}
	}
	i %= 0x10;
	int left_size = 0x10 - i;
	if (left_size < 0x10) {
		ascii_letter[i] = 0;
		for (i = 0; i < left_size; i++)
			printf("   ");
		printf("%s\n", ascii_letter);
	}
}

void setvbuf0(context* ctx) {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
	//print_diy("setvbuf0 called\n");
}

void print_diy(char *data) {
	int fd;
	for (fd = 1; fd < 2; fd++) {
		write(fd, data, strlen(data));
	}
}

void printf_diy(char *data, long int val) {
	char buff[0x100];
	sprintf(buff, data, val);
	print_diy(buff);
}

void dup_io(context *ctx, int port) {
	//int server = socket
}

typedef struct _HookHandler
{
	long int hook_addr;
	void (*handler)(context *);
	long int ret_addr;
} HookHandler;

#define PYGDB_HANDLER_MAX  0x1000
HookHandler pygdb_handler_array[PYGDB_HANDLER_MAX];
int pygdb_handler_pos  = 0;
int pygdb_handler_size = PYGDB_HANDLER_MAX;

long int  core_hook_fix_in(context *ctx) {
	long int pc;
	//void (*handler)(context *);
#ifdef ARCH_MODE_X64
	ctx->rip -= 0x5;
	pc = ctx->rip;
	ctx->rsp += sizeof(long int);
#endif

#ifdef ARCH_MODE_X32
	ctx->eip -= 0x5;
	pc = ctx->eip;
	ctx->esp += sizeof(long int);
#endif

#ifdef ARCH_MODE_ARM
	if (ctx->lr & 1 == 1)
		ctx->r15 -= 0x2;
	else
		ctx->r15 -= 0x4;
	pc = ctx->r15;
	ctx->r13 += sizeof(long int);
#endif

#ifdef ARCH_MODE_AARCH64
	ctx->x31 -= 0x4;
	pc = ctx->x31;
	ctx->x29 += sizeof(long int);
#endif
	return pc;
}

void core_hook_fix_out(context *ctx, long int ret_addr) {
	
#ifdef ARCH_MODE_X64
	ctx->rip = ret_addr;
	ctx->rsp -= sizeof(long int);
#endif

#ifdef ARCH_MODE_X32
	ctx->eip = ret_addr;
	ctx->esp -= sizeof(long int);
#endif

#ifdef ARCH_MODE_ARM
	if (ctx->lr & 1 == 1)
		ctx->r15 = ret_addr + 1;
	else
		ctx->r15 = ret_addr;
	ctx->r13 -= sizeof(long int);
#endif

#ifdef ARCH_MODE_AARCH64
	ctx->x31 = ret_addr;
	ctx->x29 -= sizeof(long int);
#endif
}

void core_hook_dispatcher(context *ctx) {
	long int pc = core_hook_fix_in(ctx);

	int i;
	for (i = 0; i < pygdb_handler_pos; i++) {
		//printf("check hook_addr[%d]: 0x%x -> 0x%x\n", i, pygdb_handler_array[i].hook_addr, pc);
		if (pygdb_handler_array[i].hook_addr == pc) {
			//printf("find handler: 0x%x\n", pc);
			pygdb_handler_array[i].handler(ctx);
			core_hook_fix_out(ctx, pygdb_handler_array[i].ret_addr);
			//printf("handler ret: 0x%x\n", ctx->rip);
			break;
		}
	}

}