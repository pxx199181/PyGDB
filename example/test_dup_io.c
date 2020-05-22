#include <stdio.h>
int main() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
	char buff[0x100];
	printf("hello world\n");
	while (1) {
		printf(">> ");
		gets(buff);
		if (memcmp(buff, "exit", 4) == 0)
			break;
		printf(buff);
		printf("\n");
	}
}