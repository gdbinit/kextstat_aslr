/*
 *     _____                              _____
 *  __| __  |__  ______  __ __   __    __|_    |__  ______  ____    _____
 * |  |/ /     ||   ___| \ ` / _|  |_ |    \      ||   ___||    |  |     |
 * |     \     ||   ___| /   \|_    _||     \     | `-.`-. |    |_ |     \
 * |__|\__\  __||______|/__/\_\ |__|  |__|\__\  __||______||______||__|\__\
 *    |_____|                            |_____|
 *
 * Kext ASLR
 *
 * A small util to kernel extensions with true address in Mountain Lion due to KASLR
 *
 * fG! - 2012 - reverser@put.as - http://reverse.put.as
 *
 * Note: This requires kmem/mem devices to be enabled
 * Edit /Library/Preferences/SystemConfiguration/com.apple.Boot.plist
 * add kmem=1 parameter, and reboot!
 *
 * To compile:
 * gcc -Wall -o readkmem readkmem.c
 *
 * v0.1 - Initial version
 *
 * You will need to supply sLoadedKexts symbol, which is not exported.
 * Disassemble the kernel and go to this method OSKext::lookupKextWithLoadTag
 * The pointer address to sLoadedKexts is moved to RDI after the call to IORecursiveLockLock
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <ctype.h>
#include <mach-o/loader.h>
#include <mach/mach_types.h>
#include <stddef.h>
#include <assert.h>

#define VERSION "0.1"

#define SLOADEDKEXTS        0xFFFFFF80008AD228
#define TEXT_BASE_ADDRESS   0xFFFFFF8000200000
#define KMOD_MAX_NAME    64

typedef uint64_t idt_t;

struct sysent64 {		/* system call table */
	int16_t		sy_narg;	/* number of args */
	int8_t		sy_resv;	/* reserved  */
	int8_t		sy_flags;	/* flags */
    uint32_t    padding;        /* padding, x86 binary against 64bits kernel would fail */
	uint64_t	sy_call;	/* implementing function */
	uint64_t	sy_arg_munge32; /* system call arguments munger for 32-bit process */
	uint64_t	sy_arg_munge64; /* system call arguments munger for 64-bit process */
	int32_t		sy_return_type; /* system call return types */
	uint16_t	sy_arg_bytes;	/* Total size of arguments in bytes for
								 * 32-bit system calls
								 */
};

// 16 bytes IDT descriptor, used for 32 and 64 bits kernels (64 bit capable cpus!)
struct descriptor_idt
{
	uint16_t offset_low;
	uint16_t seg_selector;
	uint8_t reserved;
	uint8_t flag;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t reserved2;
};

mach_vm_address_t vmaddr_slide = 0;

// prototypes
int8_t get_kernel_type (void);
idt_t  get_addr_idt (void);

void header(void);
void usage(void);
int8_t readkmem(const int32_t fd, void *buffer, const uint64_t offset, const size_t size);

/* memzero function by:
 * Copyright 2012, Mansour Moufid <mansourmoufid@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
void *memzero(void *, size_t);
void *memzero(void *mem, size_t n)
{
    size_t i, j;
    unsigned long long *q;
    unsigned long long qzero = 0ULL;
    unsigned char *b;
    unsigned char bzero = 0U;
    
    assert(mem != NULL);
    assert(n > 0);
    
    i = 0;
    
    b = mem;
    while ((size_t) b % sizeof(qzero) != 0) {
        *b = bzero;
        b++;
        i++;
        if (i >= n) {
            return mem;
        }
    }
    
    if (n-i >= sizeof(qzero)) {
        q = mem;
        q += i;
        q[0] = qzero;
        for (j = 1; j < (n-i)/sizeof(qzero); j++) {
            q[j] = q[j-1];
        }
        i += j*sizeof(qzero);
    }
    
    if (i >= n) {
        return mem;
    }
    
    b = mem;
    b += i;
    b[0] = bzero;
    for (j = 1; j < n-i; j++) {
        b[j] = b[j-1];
    }
    
    return mem;
}

// retrieve the base address for the IDT
idt_t
get_addr_idt (void)
{
	// allocate enough space for 32 and 64 bits addresses
	uint8_t idtr[10];
	__asm__ volatile ("sidt %0": "=m" (idtr));
    return *((idt_t *) &idtr[2]);
}

uint64_t
calculate_int80address(int32_t fd_kmem, const uint64_t idt_address)
{
  	// find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s
	struct descriptor_idt *int80_descriptor = NULL;
	uint64_t int80_address = 0;
	uint64_t high       = 0;
    uint32_t middle     = 0;
    
	int80_descriptor = malloc(sizeof(struct descriptor_idt));
	// retrieve the descriptor for interrupt 0x80
    // the IDT is an array of descriptors
	readkmem(fd_kmem, int80_descriptor, idt_address+sizeof(struct descriptor_idt)*0x80, sizeof(struct descriptor_idt));
    
    // we need to compute the address, it's not direct
    // extract the stub address
    high = (unsigned long)int80_descriptor->offset_high << 32;
    middle = (unsigned int)int80_descriptor->offset_middle << 16;
    int80_address = (uint64_t)(high + middle + int80_descriptor->offset_low);
	printf("[OK] Address of interrupt 80 stub is %p\n", (void*)int80_address);
    return(int80_address);
}

uint64_t
find_kernel_base(int32_t fd_kmem, const uint64_t int80_address)
{
    uint64_t temp_address   = int80_address;
    // the step amount to search backwards from int80
    uint16_t step_value     = 500; // step must be at least sizeof mach_header and a segment_command
    uint16_t length         = step_value;
    uint8_t *temp_buffer    = malloc(step_value);
    
    struct segment_command_64 *segment_command = NULL;
    while (temp_address > 0)
    {
        // read the kernel mem contents
        readkmem(fd_kmem, temp_buffer, temp_address, length);
        // iterate thru buffer contents, searching for mach-o magic value
        for (uint32_t x = 0; x < length; x++)
        {
            if (*(uint32_t*)(temp_buffer+x) == MH_MAGIC_64)
            {
                segment_command = (struct segment_command_64*)(temp_buffer+x+sizeof(struct mach_header_64));
                if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
                {
                    printf("[OK] Found kernel mach-o header address at %p\n", (void*)(temp_address+x));
                    return((uint64_t)(temp_address+x));
                }
            }
        }
        // verify if next block to be read is valid or not
        // adjust the step value to a smaller value so we can proceed
        while(readkmem(fd_kmem, temp_buffer, temp_address-step_value, length) == -2)
        {
            step_value = 1; // we could find out which is the biggest acceptable value
            // but it seems like a waste of time - I'm an Economist :P
            // we can read smaller values to avoid overlapping
            length = sizeof(struct mach_header_64) + sizeof(struct segment_command_64);
        }
        // check for int overflow
        if (temp_address - step_value > temp_address)
            break;
        temp_address -= step_value;
    }
    return(0);
}

int8_t
readkmem(const int32_t fd, void *buffer, const uint64_t offset, const size_t size)
{
	if(lseek(fd, offset, SEEK_SET) != offset)
	{
		fprintf(stderr,"[ERROR] Error in lseek. Are you root? \n");
		return(-1);
	}
    ssize_t bytes_read = read(fd, buffer, size);
	if(bytes_read != size)
	{
		fprintf(stderr,"[ERROR] Error while trying to read from kmem. Asked %ld bytes from offset %llx, returned %ld.\n", size, offset, bytes_read);
		return(-2);
	}
    return(0);
}

void
usage(void)
{
	fprintf(stderr,"kextstat_aslr\n");
	exit(1);
}

void
header(void)
{
    fprintf(stderr," _____         _   _____     _\n");
    fprintf(stderr,"|  |  |___ _ _| |_|  _  |___| |___\n");
    fprintf(stderr,"|    -| -_|_'_|  _|     |_ -| |  _|\n");
    fprintf(stderr,"|__|__|___|_,_|_| |__|__|___|_|_|\n");
	fprintf(stderr,"       KextASLR v%s - (c) fG!\n",VERSION);
	fprintf(stderr,"-----------------------------------\n");
}

int main(int argc, char ** argv)
{
	header();
    
	if (argc < 1)
	{
		usage();
	}
	
	// we need to run this as root
	if (getuid() != 0)
	{
		printf("[ERROR] Please run me as root!\n");
		exit(1);
	}
		
    int32_t fd_kmem;
    
	if((fd_kmem = open("/dev/kmem",O_RDWR)) == -1)
	{
		fprintf(stderr,"[ERROR] Error while opening /dev/kmem. Is /dev/kmem enabled?\n");
		fprintf(stderr,"Add parameter kmem=1 to /Library/Preferences/SystemConfiguration/com.apple.Boot.plist\n");
		exit(1);
	}
    
    // find kernel base address
    // retrieve int80 address
    idt_t idt_address = get_addr_idt();
    uint64_t int80_address = calculate_int80address(fd_kmem, idt_address);
    
    uint64_t kernel_base = find_kernel_base(fd_kmem, int80_address);
    if (kernel_base == 0)
    {
        fprintf(stderr, "[ERROR] Could not find kernel base address!\n");
        exit(1);
    }
    uint64_t kaslr_slide = kernel_base - TEXT_BASE_ADDRESS;
    printf("[INFO] Kernel ASLR slide is 0x%llx\n", kaslr_slide);
    // now we can have the address of pointer to sLoadedKexts
    mach_vm_address_t sLoadedKexts = SLOADEDKEXTS + kaslr_slide;
    mach_vm_address_t sLoadedKexts_object;
    // read where sLoadedKexts is pointing to so we can get the OSArray object
    readkmem(fd_kmem, &sLoadedKexts_object, sLoadedKexts, 8);
    printf("[INFO] sLoadedKexts OSArray object located at 0x%llx\n", sLoadedKexts_object);
    unsigned int kexts_count;
    readkmem(fd_kmem, &kexts_count, sLoadedKexts_object+0x20, sizeof(unsigned int));
    printf("[INFO] Total kexts loaded %d\n", kexts_count);
    mach_vm_address_t array_ptr;
    readkmem(fd_kmem, &array_ptr, sLoadedKexts_object+0x18, sizeof(mach_vm_address_t));
    printf("[INFO] Array of OSKext starts at 0x%llx\n", array_ptr);
    mach_vm_address_t OSKext_object[kexts_count];
    readkmem(fd_kmem, &OSKext_object, array_ptr, sizeof(OSKext_object));
    printf("Index  Refs  Address             Size        Name (Version) <Linked Against>\n");
    for (unsigned int i = 0; i < kexts_count; i++)
    {
//        printf("0x%llx\n", OSKext_object[i]);
        mach_vm_address_t kmod_info_ptr;
        readkmem(fd_kmem, &kmod_info_ptr, OSKext_object[i]+0x48, sizeof(kmod_info_ptr));
        kmod_info_t kmod_info;
        readkmem(fd_kmem, &kmod_info, kmod_info_ptr, sizeof(kmod_info_t));
//        printf("Kmod at 0x%llx\n", kmod_info_ptr);
        char name[KMOD_MAX_NAME];
        readkmem(fd_kmem, &name, kmod_info_ptr+0x10, sizeof(name));
        printf("%5d  %4d  0x%016llx  0x%-8x  %s (%s)\n", i, kmod_info.reference_count, kmod_info.address, kmod_info.size, kmod_info.name, kmod_info.version);
//        printf("name %s\n", kmod_info.name);
//        printf("address %llx\n", kmod_info.address);
    }
end:
	return 0;
}
