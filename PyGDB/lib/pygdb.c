#include <stdio.h>
#include "pygdb.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>  
#include <arpa/inet.h>  

void core_hexdump(unsigned char *data, int size, char *banner)
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

void core_setvbuf0() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
}

void core_log(int fd, char *data) {
	write(fd, data, strlen(data));
}

void core_logf(int fd, char *data, long int val) {
	char buff[0x100];
	sprintf(buff, data, val);
	core_log(fd, buff);
}

int core_build_server(char *ip, int port) {
	int server = socket(AF_INET, SOCK_STREAM, 0);
	/*
	struct sockaddr_in {
		 unsigned short		 sin_family;	
		 unsigned short int	 sin_port;	  
		 struct in_addr		 sin_addr;	  
		 unsigned char		  sin_zero[8];   
	};
	*/
	struct sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	sockAddr.sin_family	  = AF_INET;
	sockAddr.sin_port		= htons(port);
	sockAddr.sin_addr.s_addr = inet_addr(ip);
	int option = 1;
	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
		printf("setsockopt error\n");
		return -1;
	}
	if (bind(server, (struct sockaddr *)&sockAddr, 0x10) < 0) {
		printf("bind error\n");
		return -1;
	}

	if (listen(server, 0) < 0) {
		printf("listen error\n");
		return -1;
	}
	int client = accept(server, 0, 0);
	if (client < 0) {
		printf("accept error\n");
		return -1;
	}
	return client;
}


int core_build_client(char *ip, int port) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	/*
	struct sockaddr_in {
		 unsigned short		 sin_family;	
		 unsigned short int	 sin_port;	  
		 struct in_addr		 sin_addr;	  
		 unsigned char		  sin_zero[8];   
	};
	*/
	struct sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	sockAddr.sin_family	  = AF_INET;
	sockAddr.sin_port		= htons(port);
	sockAddr.sin_addr.s_addr = inet_addr(ip);
	int option = 1;
	if (connect(sock, (struct sockaddr *)&sockAddr, 0x10) < 0) {
		printf("bind error\n");
		return -1;
	}

	return sock;
}

int core_dup_io(char *ip, int port, int *fd_list, int fd_count, int mode) {

	int sock;
	if (mode == 1) {
	 	sock = core_build_server(ip, port);
	} else {
		sock = core_build_client(ip, port);
	}
	int i;
	for(i = 0; i < fd_count; i++) {
		dup2(sock, fd_list[i]);
	}
	return sock;
}

void parse_sock_info(char *addrData, char* sockInfo) {
	int family = *(short int*)(addrData);
	char ipInfo[0x40];
	int port = ntohs(*(short int*)(addrData + 2));
	strcpy(ipInfo, "");
	strcpy(sockInfo, "");
	if (family == AF_INET) {
		if (inet_ntop(AF_INET, addrData + 4, ipInfo, 0x10) < 0)
			return ;
		sprintf(sockInfo, "%s:%d", ipInfo, port);
	} else if (family == AF_INET6) {
		if (inet_ntop(AF_INET, addrData + 8, ipInfo, 0x20) < 0)
			return ;
		sprintf(sockInfo, "[%s]:%d", ipInfo, port);		
	}
}

void get_file_info(int fd, char *data, int max_size) {
	char filename[0x100] = {0};
	sprintf(filename, "/proc/self/fd/%d", fd);
	int size = readlink(filename, data, max_size);
	if (size <= 0) {
		strcpy(data, "");
	} else {
		data[size] = 0;
	}
}

void get_sock_info(int sock, char *data, int max_size) {
	char addrData[0x20] = {0};
	char sockInfo[0x40] = {0};
	int size = 0x20;
	strcpy(data, "");
	if (getsockname(sock, addrData, &size) == 0) {
		parse_sock_info(addrData, sockInfo);
		strcat(data, sockInfo);
	}
	memset(addrData, 0x0, 0x20);
	size = 0x20;
	strcpy(sockInfo, "");
	if (getpeername(sock, addrData, &size) == 0) {
		parse_sock_info(addrData, sockInfo);
		if (strlen(sockInfo) != 0 && strlen(data) != 0)
			strcat(data, "<=>");
		strcat(data, sockInfo);
	}
}

void core_get_fd_info(int fd, char *data) {
	char info[0x100] = {0};
	strcpy(data, "");
	get_file_info(fd, info, 0x100);
	strcpy(data, info);
	if (memcmp(info, "socket:", 0x7) == 0 || strlen(info) == 0) {
		get_sock_info(fd, info, 0x100);
		if (strlen(info) != 0)
			strcpy(data, info);
	}
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