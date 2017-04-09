obj-m += my_disk.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules



