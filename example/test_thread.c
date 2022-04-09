#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

void readfile(char *filename, char *buff, int size) {
	FILE *fp = fopen(filename, "rb");
	fread(buff, 1, size, fp);
	fclose(fp);
	return ;
}

int randval(int b, int e) {
	int val = rand()&0x7fffffff;
	return (val % (e - b)) + b; 
}

void *thread_job(void *s)
{
	int i;
	char buff[0x100];
	int count = 0;
	while (count < 10000) {
    	printf("this is 1\n");
    	for(i = 0; i < 2; i++) {
    		sleep(1);
    	}
    	readfile("./test_thread", buff, 0x100);
    	int b_pos = randval(0, 0xf0); 
    	for(i = b_pos; i < b_pos + 0x10; i++) {
    		printf("%02x ", (unsigned char)buff[i]);
    	}
    	printf("\n");
    	count += 1;
	}
}
void *thread_job1(void *s)
{	
	int i;
	int sumall = 0;
	int count = 0;
	while (count < 10000) {
    	write(1, "xxxxxxxxxxxxx 2\n", 16);
    	for (i = 0; i < 0x10000; i++) {
    		sumall += 1;
    	}
    	sleep(1);
    	printf("res: %d\n", sumall);
    	count += 1;
	}
}

int main(void)
{
	srand(time(0));
    pthread_t tid,tid1,tid2;
    pthread_create(&tid, NULL, thread_job, NULL);
    pthread_create(&tid1, NULL, thread_job1, NULL);
    pthread_create(&tid2, NULL, thread_job1, NULL);


    pthread_join(tid,NULL);
    pthread_join(tid1,NULL);
    pthread_join(tid2,NULL);
    exit(0);
}