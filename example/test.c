#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char **argv){
	long int handle = dlopen("/usr/local/lib/python2.7/dist-packages/PyGDB-1.0.0-py2.7.egg/PyGDB/lib/libpygdb.so", 1);
	printf("handle: %p\n", handle);
	long int addr = dlsym(handle, "core_log");
	printf("core_log: %p\n", addr);
	
	printf("lib: %s\n", argv[1]);
	handle = dlopen(argv[1], 1);
	if (handle == 0) {
		printf("dlerror: %s\n", dlerror());
	}
	printf("handle: %p\n", handle);
	addr = dlsym(handle, "show_context");
	printf("show_context: %p\n", addr);

}