#include "pygdb.h"
#include <stdio.h>

void hexdump(unsigned char *data, int size, char *banner)
{
	core_hexdump(data, size, banner);
}

void setvbuf0(context* ctx) {
	core_setvbuf0();
}

void show_context(context* ctx) {
	core_log(1, "in context\n");
	core_logf(1, "rax: 0x%llx\n", ctx->rax);
	core_logf(1, "rbx: 0x%llx\n", ctx->rbx);
	core_logf(1, "rcx: 0x%llx\n", ctx->rcx);
	core_logf(1, "hook addr: 0x%llx\n", ctx->rip);
	core_logf(1, "hook rsp: 0x%llx\n", ctx->rsp);
}

void dup_io(context *ctx, int port) {
	//int server = socket
	int fd_list[3] = {0, 1, 2};
	core_dup_io("127.0.0.1", 12345, fd_list, 3);
}