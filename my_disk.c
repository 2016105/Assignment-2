#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/genhd.h> 				// For basic block driver framework
#include <linux/blkdev.h> 				// For at least, struct block_device_operations
#include <linux/hdreg.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/errno.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tanya");
MODULE_DESCRIPTION("DISK ON RAM");
MODULE_ALIAS_BLOCKDEV_MAJOR(my_disk_major);

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*a))				//macro defined to give size of array
#define SECTOR_SIZE 512										
#define MBR_SIZE 512
#define MBR_DISK_SIGNATURE_OFFSET 440
#define MBR_DISK_SIGNATURE_SIZE 4
#define PARTITION_TABLE_OFFSET 446 
#define PARTITION_ENTRY_SIZE 16
#define PARTITION_TABLE_SIZE 64
#define MBR_SIGNATURE_OFFSET 510
#define MBR_SIGNATURE_SIZE 2
#define MBR_SIGNATURE 0xAA55
#define BR_SIZE SECTOR_SIZE
#define BR_SIGNATURE_OFFSET 510
#define BR_SIGNATURE_SIZE 2
#define BR_SIGNATURE 0xAA55

#define MY_DISK_SECTOR_SIZE 512
#define MY_DISK_DEVICE_SIZE 1024							//no. of secotrs, so total size becomes = 1024 * 512 = 512KiB
#define MY_DISK_FIRST_MINOR 0
#define MY_DISK_MINOR_COUNT 16	
								
static u_int my_disk_major = 0;
static u8 *dev_data;

typedef struct
{
	unsigned char boot_type;
	unsigned char start_head;
	unsigned char start_sec:6;
	unsigned char start_cyl_hi:2;
	unsigned char start_cyl;
	unsigned char part_type;
	unsigned char end_head;
	unsigned char end_sec:6;
	unsigned char end_cyl_hi:2;
	unsigned char end_cyl;
	unsigned int abs_start_sec;
	unsigned int sec_in_part;
} PartEntry;

typedef PartEntry PartTable[4];

static PartTable def_part_table = 
{
	{
		boot_type: 0x00,					//primary partition 1 which is inactive (0x00) 
		start_head: 0x00,
		start_sec: 0x2,
		start_cyl: 0x00,
		part_type: 0x83,					//partiton type = linux
		end_head: 0x00,
		end_sec: 0x20,
		end_cyl: 0x09,
		abs_start_sec: 0x00000001,			// start of sector from 1
		sec_in_part: 0x0000013F				//tottal no of sectors in this partition =  319
	},
	
	{
		boot_type: 0x00,					//extended partition 2 which is inactive (0x00) 
		start_head: 0x00,
		start_sec: 0x1,
		start_cyl: 0x0A,
		part_type: 0x05,					//partiton type = linux
		end_head: 0x00,
		end_sec: 0x20,
		end_cyl: 0x13,
		abs_start_sec: 0x00000140,			// start of sector from 320
		sec_in_part: 0x00000140				//tottal no of sectors in this partition =  320
	},
	{
		boot_type: 0x00,					//primary partition 3 which is inactive (0x00)
		start_head: 0x00,
		start_sec: 0x1,
		start_cyl: 0x14,
		part_type: 0x07,					//partiton type = NTFS
		end_head: 0x00,
		end_sec: 0x20,
		end_cyl: 0x1F,
		abs_start_sec: 0x00000280,			// start of sector from 640
		sec_in_part: 0x00000107				//tottal no of sectors in this partition = 263
	},
	{
		boot_type: 0x00,					//primary partition 4 which is inactive (0x00)
		start_head: 0x00,
		start_sec: 0x1,
		start_cyl: 0x15,
		part_type: 0x83,					//partiton type = linux
		end_head: 0x00,
		end_sec: 0x20,
		end_cyl: 0x1F,
		abs_start_sec: 0x00000387,			// start of sector from  903
		sec_in_part: 0x00000079				//tottal no of sectors in this partition = 121
		
	}
	
};

static unsigned int def_log_part_br_cyl[] = {0x0A, 0x0E, 0x12};
static const PartTable def_log_part_table[] =
{
	{
		{
			boot_type: 0x00,				//logical parition 1 
			start_head: 0x00,
			start_sec: 0x2,
			start_cyl: 0x0A,
			part_type: 0x83,				//partition type = linux
			end_head: 0x00,
			end_sec: 0x20,
			end_cyl: 0x0D,
			abs_start_sec: 0x00000001,		
			sec_in_part: 0x0000006F
		},	
		{
			boot_type: 0x00,
			start_head: 0x00,
			start_sec: 0x1,
			start_cyl: 0x0E,
			part_type: 0x05,				//parition type is extended. This is for the next logical partiton
			end_head: 0x00,
			end_sec: 0x20,
			end_cyl: 0x11,
			abs_start_sec: 0x00000080,
			sec_in_part: 0x00000080
		},
	},
	{
		{
			boot_type: 0x00,
			start_head: 0x00,
			start_sec: 0x2,
			start_cyl: 0x0E,
			part_type: 0x24,
			end_head: 0x00,
			end_sec: 0x20,
			end_cyl: 0x11,
			abs_start_sec: 0x00000001,
			sec_in_part: 0x0000006F
		},
		{
			boot_type: 0x00,
			start_head: 0x00,
			start_sec: 0x1,
			start_cyl: 0x12,
			part_type: 0x05,
			end_head: 0x00,
			end_sec: 0x20,
			end_cyl: 0x13,
			abs_start_sec: 0x00000100,
			sec_in_part: 0x00000040
		},
	},
	{
		{
			boot_type: 0x00,
			start_head: 0x00,
			start_sec: 0x2,
			start_cyl: 0x12,
			part_type: 0x82,				
			end_head: 0x00,
			end_sec: 0x20,
			end_cyl: 0x13,
			abs_start_sec: 0x00000001,
			sec_in_part: 0x0000003F
		},
	}
};

static void copy_mbr(u8 *disk)
{
	memset(disk, 0x0, MBR_SIZE);
	*(unsigned long *)(disk + MBR_DISK_SIGNATURE_OFFSET) = 0x36E5756D;
	memcpy(disk + PARTITION_TABLE_OFFSET, &def_part_table, PARTITION_TABLE_SIZE);
	*(unsigned short *)(disk + MBR_SIGNATURE_OFFSET) = MBR_SIGNATURE;
}

static void copy_br(u8 *disk, int start_cylinder, const PartTable *part_table)
{
	disk += (start_cylinder * 32  * SECTOR_SIZE);
	memset(disk, 0x0, BR_SIZE);
	memcpy(disk + PARTITION_TABLE_OFFSET, part_table,
		PARTITION_TABLE_SIZE);
	*(unsigned short *)(disk + BR_SIGNATURE_OFFSET) = BR_SIGNATURE;
}
void copy_mbr_n_br(u8 *disk)
{
	int i;

	copy_mbr(disk);
	for (i = 0; i < ARRAY_SIZE(def_log_part_table); i++)
	{
		copy_br(disk, def_log_part_br_cyl[i], &def_log_part_table[i]);
	}
}

static struct my_disk_device
{
	unsigned int size;						//size of the device in sectors
	spinlock_t lock;						//concurrent protection of request queue
	short users;							//how many users
	struct request_queue *my_disk_queue;	//device request queue
	struct gendisk *my_disk_disk;			//gendisk structure

}my_disk_dev;
/*
static int my_disk_open(struct block_device *bdev, fmode_t mode)
{
	unsigned unit = iminor(bdev->bd_inode);
	
	printk(KERN_INFO "MY_DISK: device opened\n");
	printk(KERN_INFO "MY_DISK: inode number is %d\n", unit);
	
	spin_lock(&my_disk_dev.lock);
	if(unit > MY_DISK_MINOR_COUNT)
		return -ENOMEM;
	my_disk_dev.users++;
	spin_unlock(&my_disk_dev.lock);
	
	return 0;
}

static void my_disk_release(struct gendisk *disk, fmode_t mode)
{
	printk(KERN_INFO "MY_DISK: device closed\n");
	
	spin_lock(&my_disk_dev.lock);
	my_disk_dev.users--;
	spin_unlock(&my_disk_dev.lock);
	
}

static int my_disk_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	geo->heads = 1;
	geo->cylinders = 32;
	geo->sectors = 32;
	geo->start = 0;
	return 0;
}
*/

static int my_disk_transfer(struct request *req, sector_t start_sector, unsigned int sector_cnt ,int write)
{
	
#define BV_PAGE(bv)		((bv).bv_page)
#define BV_OFFSET(bv)	((bv).bv_offset)
#define BV_LEN(bv)		((bv).bv_len)

	struct bio_vec bv;
	struct req_iterator iter;
	
	sector_t sector_offset;
	unsigned int sectors;
	u8 *buffer;
	int ret = 0;
	
	sector_offset = 0;
	rq_for_each_segment(bv, req, iter)
	{
		buffer = page_address(BV_PAGE(bv)) + BV_OFFSET(bv);
		if(BV_LEN(bv) % MY_DISK_SECTOR_SIZE != 0)
		{
			printk(KERN_INFO "operation cannot happen because bio size (%d) is not a multiple of MY_DISK_SECTOR_SIZE(%d)\n", BV_LEN(bv), MY_DISK_SECTOR_SIZE);
			ret = -EIO;
		}
		sectors = BV_LEN(bv) / MY_DISK_SECTOR_SIZE;
		printk(KERN_INFO "MY_DISK: %llu, sector offset: %llu, buffer: %p, length: %u sectors\n", (unsigned long long)(start_sector), (unsigned long long)(sector_offset), buffer, sectors);
		
		if(write)
			memcpy(dev_data + (start_sector + sector_offset) * MY_DISK_SECTOR_SIZE, buffer, sectors * MY_DISK_SECTOR_SIZE);
		else 
				memcpy(buffer, dev_data + (start_sector + sector_offset) * MY_DISK_SECTOR_SIZE, sectors * MY_DISK_SECTOR_SIZE);

		sector_offset += sectors;
	}
	if(sector_offset != sector_cnt)
	{
		printk(KERN_ERR "MY_DISK: the required bio information doesnot matches with the request information");
		ret = -EIO;
	}
	return ret;
}

static void my_disk_request(struct request_queue *q)
{
	struct request *req;
	int ret;
	
	while((req = blk_fetch_request(q)) != NULL)
	{
#if 0
		if(!blk_fs_request(req))
		{
			printk(KERN_INFO "MY_DISK: skip non-fs request\n");
			__blk_end_request_all(req, 0);
			continue;
		}
#endif
		ret = my_disk_transfer(req, blk_rq_pos(req), blk_rq_sectors(req), rq_data_dir(req));
		__blk_end_request_all(req, ret);
	}
}

static struct block_device_operations my_disk_fops = 
{
	.owner	=	THIS_MODULE,
	//.open	=	my_disk_open,
	//.release=	my_disk_release,
	//.getgeo	=	my_disk_getgeo,
};

static int __init mydisk_init(void)
{
	dev_data = vmalloc(MY_DISK_SECTOR_SIZE * MY_DISK_DEVICE_SIZE);
	if(dev_data == NULL)
		return -ENOMEM;
	
	copy_mbr_n_br(dev_data);
	
	my_disk_dev.size = MY_DISK_DEVICE_SIZE;
	
	my_disk_major = register_blkdev(my_disk_major, "my_disk");
	if(my_disk_major <= 0)
	{
		printk(KERN_ERR "MY_DISK: registeration failed\n");
		vfree(dev_data);
		return -EBUSY;
	}
	
	spin_lock_init(&my_disk_dev.lock);
	my_disk_dev.my_disk_queue = blk_init_queue(my_disk_request, &my_disk_dev.lock);
	if(my_disk_dev.my_disk_queue == NULL)
	{
		printk(KERN_ERR "MY_DISK: blk_init_queue failure\n");
		unregister_blkdev(my_disk_major, "my_disk");
		vfree(dev_data);
		return -ENOMEM;
	}
	
	my_disk_dev.my_disk_disk = alloc_disk(MY_DISK_MINOR_COUNT);
	if(!my_disk_dev.my_disk_disk)
	{
		printk(KERN_ERR "MY_DISK: alloc_disk failure\n");
		blk_cleanup_queue(my_disk_dev.my_disk_queue);
		unregister_blkdev(my_disk_major, "my_disk");
		vfree(dev_data);
		return -ENOMEM;
	}
	
	my_disk_dev.my_disk_disk->major = my_disk_major;
	my_disk_dev.my_disk_disk->first_minor = MY_DISK_FIRST_MINOR;
	my_disk_dev.my_disk_disk->fops = &my_disk_fops;
	my_disk_dev.my_disk_disk->private_data = &my_disk_dev;
	my_disk_dev.my_disk_disk->queue = my_disk_dev.my_disk_queue;
	
	sprintf(my_disk_dev.my_disk_disk->disk_name, "my_disk");
	set_capacity(my_disk_dev.my_disk_disk, my_disk_dev.size);
	add_disk(my_disk_dev.my_disk_disk);
	printk(KERN_INFO "MY_DISK: MY_DISK Block Driver initialised (%d sectors; %d bytes)\n",my_disk_dev.size, my_disk_dev.size * MY_DISK_SECTOR_SIZE);

	return 0;
}

static void __exit mydisk_exit(void)
{
	del_gendisk(my_disk_dev.my_disk_disk);
	put_disk(my_disk_dev.my_disk_disk);
	blk_cleanup_queue(my_disk_dev.my_disk_queue);
	unregister_blkdev(my_disk_major, "my_disk");
	vfree(dev_data);
}

module_init(mydisk_init);
module_exit(mydisk_exit);
