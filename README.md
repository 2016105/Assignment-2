DISK ON RAM

Introduction:

The objective of this assignment is to create a block device called "mydisk". This will be allocated 512KiB of space in memory and simulated as a separated block device. Also "mydisk" is divided into 3 primary + 1 extended partition. Within extended partition it contains 3 logical partitions.

my_disk.c:

This kernel module creates block device as per the object. The open, release and geometry functions are commented in this code since they are not being used. But if you need to use them you can remove the comments.

How to build:
copy the two files from this repository : my_disk.c and Makefile and type the following commands in order: 

$ make 

$ sudo insmod ./my_disk.ko

Output:
This will create block device files (/dev/my_disk*). /dev/my_disk is the entire disk of 512KiB size. my_disk1, my_disk2, my_disk3, my_disk4 are primary partition my_disk2 being the extended partition and containing the 3 logical partitions my_disk5, my_disk6, my_disk7.

Type the following command in order to verify the output:
$ ls -l /dev/my_disk
this command will display your block device file in /dev directory.

$ ls -l /dev/my_disk*
this command will display all partitions as file in /dev directory.

$ sudo fdisk -l
this command will display my_disk partition, size of partitions, partition types.


