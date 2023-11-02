obj-m := wg-firewall-kern.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	$(CC) wg-firewall-usr.c -o wg-firewall-usr
	sudo insmod wg-firewall-kern.ko
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	sudo rmmod wg-firewall-kern.ko
	rm wg-firewall-usr
	rm *.mod *.ko *.o	
