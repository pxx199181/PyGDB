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
#include <stdio.h>

#define ARCH_MODE_X64
//#define ARCH_MODE_X32
//#define ARCH_MODE_ARM
//#define ARCH_MODE_AARCH64

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

void show_contenxt(context* ctx) {
	print_diy("in context\n");
	printf_diy("rax: 0x%llx\n", ctx->rax);
	printf_diy("rbx: 0x%llx\n", ctx->rbx);
	printf_diy("rcx: 0x%llx\n", ctx->rcx);
	printf_diy("hook addr: 0x%llx\n", ctx->rip);
	printf_diy("hook rsp: 0x%llx\n", ctx->rsp);
}

void dup_io(context *ctx, int port) {
	//int server = socket
}
