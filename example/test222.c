#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


int main(int argc, char**argv) {

	printf("%x\n", O_RDWR);
	printf("%x\n", O_APPEND);
	printf("%x\n", O_RDWR|O_APPEND|O_CREAT);
	__asm__ __volatile__(".byte 0x90;.byte 0x90;"::);
	__asm__ __volatile__("mov %%eax, %%eax;mov %%eax, %%eax;"::);
	__asm__ __volatile__(".byte 0x90;.byte 0x90;"::);
	//return 2;
}