#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <sys/socket.h>

int main(int argc, char**argv) {

	printf("%x\n", O_RDWR);
	printf("%x\n", O_APPEND);
	printf("%x\n", O_RDWR|O_APPEND|O_CREAT);
	__asm__ __volatile__(".byte 0x90;.byte 0x90;"::);
	__asm__ __volatile__("mov %%eax, %%eax;mov %%eax, %%eax;"::);
	__asm__ __volatile__(".byte 0x90;.byte 0x90;"::);

	printf("AF_INET			: %d\n", AF_INET);
	printf("SOCK_STREAM		: %d\n", SOCK_STREAM);
	printf("SOL_SOCKET		: %d\n", SOL_SOCKET);
	printf("SO_REUSEADDR	: %d\n", SO_REUSEADDR);
	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

	char serveraddr[0x10] = {0};
	*(long long int*)serveraddr = 0x100007f44440002;
	int option = 1;
	if (bind(listen_fd, &serveraddr, 0x10) < 0)
		printf("bind error\n");
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&option, sizeof(option)) < 0)
		printf("setsockopt error\n");
	if (listen(listen_fd, 10) < 0)
		printf("listen error\n");;

	printf("listen_fd:[%d]\n", listen_fd);
	FILE *fp = fopen("./test222", "rb");
	int fd = fileno(fp);
	char data[5] = {0};
	read(fd, data, 4);
	printf("fd:[%d] -> data: %s\n", fd, data);

	alarm(60);

	close(fd);
	close(listen_fd);
	//return 2;
}