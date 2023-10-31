obj-m := chardevice.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	$(CC) chardevice_usr.c -o chardevice_usr
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm chardevice_usr
	rm *.mod *.ko *.o	
