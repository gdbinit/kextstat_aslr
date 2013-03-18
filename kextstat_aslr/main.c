/*
 *     _____                              _____
 *  __| __  |__  ______  __ __   __    __|_    |__  ______  ____    _____
 * |  |/ /     ||   ___| \ ` / _|  |_ |    \      ||   ___||    |  |     |
 * |     \     ||   ___| /   \|_    _||     \     | `-.`-. |    |_ |     \
 * |__|\__\  __||______|/__/\_\ |__|  |__|\__\  __||______||______||__|\__\
 *    |_____|                            |_____|
 *
 * Kextstat ASLR
 *
 * A small util to kernel extensions with true address in Mountain Lion due to KASLR
 *
 * (c) fG!, 2012,2013 - reverser@put.as - http://reverse.put.as
 *
 * Note: This requires kmem/mem devices to be enabled
 * Edit /Library/Preferences/SystemConfiguration/com.apple.Boot.plist
 * add kmem=1 parameter, and reboot!
 *
 * v0.1 - Initial version
 * v0.2 - Retrieve kaslr slide via kas_info() syscall. Thanks to posixninja for the tip :-)
 * v0.3 - Cleanups
 *
 * You will need to supply sLoadedKexts symbol, which is not exported.
 * Disassemble the kernel and go to this method OSKext::lookupKextWithLoadTag
 * The pointer address to sLoadedKexts is moved to RDI after the call to IORecursiveLockLock
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
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
#include <sys/syscall.h>
#include <errno.h>

#define VERSION "0.3"

#define LOOKUPKEXTWITHLOADTAG "__ZN6OSKext21lookupKextWithLoadTagEj" // OSKext::lookupKextWithLoadTag symbol
#define SLOADEDKEXTS        0xFFFFFF80008AD228
#define KMOD_MAX_NAME       64

typedef uint64_t idt_t;

struct sysent64 {		        /* system call table */
	int16_t		sy_narg;	    /* number of args */
	int8_t		sy_resv;	    /* reserved  */
	int8_t		sy_flags;	    /* flags */
    uint32_t    padding;        /* padding, x86 binary against 64bits kernel would fail */
	uint64_t	sy_call;	    /* implementing function */
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

// from xnu/bsd/sys/kas_info.h
#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR     (0)     /* returns uint64_t     */
#define KAS_INFO_MAX_SELECTOR           (1)
int kas_info(int selector, void *value, size_t *size);

// prototypes
int8_t get_kernel_type (void);
idt_t  get_addr_idt (void);
uint64_t calculate_int80address(int32_t fd_kmem, const uint64_t idt_address);
uint64_t find_kernel_base(int32_t fd_kmem, const uint64_t int80_address);
void header(void);
void usage(void);
int8_t readkmem(const int32_t fd, void *buffer, const uint64_t offset, const size_t size);

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
	uint64_t high          = 0;
    uint32_t middle        = 0;
    
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
    uint16_t step_value     = 4096; // step must be at least sizeof mach_header and a segment_command
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
            if (*(uint32_t*)(temp_buffer + x) == MH_MAGIC_64)
            {
                segment_command = (struct segment_command_64*)(temp_buffer + x + sizeof(struct mach_header_64));
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
        if (temp_address - step_value > temp_address) break;
        
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

/*
 * read the target file into a buffer
 */
static uint64_t
read_target(uint8_t **targetBuffer, const char *target)
{
    FILE *in_file = NULL;
	
    in_file = fopen(target, "r");
    if (!in_file)
    {
		fprintf(stderr, "[ERROR] Could not open target file %s!\n", target);
        exit(1);
    }
    if (fseek(in_file, 0, SEEK_END))
    {
		fprintf(stderr, "[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    long fileSize = ftell(in_file);
    
    if (fseek(in_file, 0, SEEK_SET))
    {
		fprintf(stderr, "[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
    *targetBuffer = malloc(fileSize * sizeof(uint8_t));
    
    if (*targetBuffer == NULL)
    {
        fprintf(stderr, "[ERROR] Malloc failed!\n");
        exit(1);
    }
    
    fread(*targetBuffer, fileSize, 1, in_file);
	if (ferror(in_file))
	{
		fprintf(stderr, "[ERROR] fread failed at %s\n", target);
        free(*targetBuffer);
		exit(1);
	}
    fclose(in_file);
    return(fileSize);
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

/*
 * lame inline asm to use the kas_info() syscall. beware the difference if we want 64bits syscalls!
 */
void
get_kaslr_slide(size_t *size, uint64_t *slide)
{
    // this is needed for 64bits syscalls!!!
    // good post about it http://thexploit.com/secdev/mac-os-x-64-bit-assembly-system-calls/
#define SYSCALL_CLASS_SHIFT                     24
#define SYSCALL_CLASS_MASK                      (0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK                     (~SYSCALL_CLASS_MASK)
#define SYSCALL_CLASS_UNIX                      2
#define SYSCALL_CONSTRUCT_UNIX(syscall_number) \
        ((SYSCALL_CLASS_UNIX << SYSCALL_CLASS_SHIFT) | \
        (SYSCALL_NUMBER_MASK & (syscall_number)))
    
    uint64_t syscallnr = SYSCALL_CONSTRUCT_UNIX(SYS_kas_info);
    uint64_t selector = KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR;
    int result = 0;
    __asm__ ("movq %1, %%rdi\n\t"
             "movq %2, %%rsi\n\t"
             "movq %3, %%rdx\n\t"
             "movq %4, %%rax\n\t"
             "syscall"
             : "=a" (result)
             : "r" (selector), "m" (slide), "m" (size), "a" (syscallnr)
             : "rdi", "rsi", "rdx", "rax"
             );
}

/*
 * where all the fun begins
 */
int main(int argc, char ** argv)
{

	header();
    // XXX: support sLoadedKexts address as a parameter instead of fixed address
//	if (argc < 1)
//	{
//		usage();
//	}

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
    
    // get info from the kernel at disk
    uint8_t *kernel_buffer = NULL;
    read_target(&kernel_buffer, "/mach_kernel");
    // solve the OSKext::lookupKextWithLoadTag symbol
    solve_symbol(LOOKUPKEXTWITHLOADTAG);
    
    // find kernel base address
    // retrieve int80 address and then search backwards until the mach-o header
    idt_t idt_address = get_addr_idt();
    uint64_t int80_address = calculate_int80address(fd_kmem, idt_address);
    
    uint64_t kernel_base = find_kernel_base(fd_kmem, int80_address);
    if (kernel_base == 0)
    {
        fprintf(stderr, "[ERROR] Could not find kernel base address!\n");
        exit(1);
    }
    
    // retrieve kernel aslr slide using kas_info() syscall
    // this is a private kernel syscall but we can access it in Mountain Lion if we link against System.framework
    // or we can use my lame asm function get_kaslr_slide() :-)
    size_t kaslr_size = 0;
    uint64_t kaslr_slide = 0;
    kaslr_size = sizeof(kaslr_slide);
    int ret = kas_info(KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR, &kaslr_slide, &kaslr_size);
    if (ret != 0)
    {
        printf("[ERROR] Could not get kernel ASLR slide info from kas_info(). Errno: %d\n", errno);
        exit(1);
    }
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
    printf("Index  Refs  Address             Size        Name (Version)\n");
    for (unsigned int i = 0; i < kexts_count; i++)
    {
        mach_vm_address_t kmod_info_ptr;
        readkmem(fd_kmem, &kmod_info_ptr, OSKext_object[i]+0x48, sizeof(kmod_info_ptr));
        kmod_info_t kmod_info;
        readkmem(fd_kmem, &kmod_info, kmod_info_ptr, sizeof(kmod_info_t));
        char name[KMOD_MAX_NAME];
        readkmem(fd_kmem, &name, kmod_info_ptr+0x10, sizeof(name));
        printf("%5d  %4d  0x%016llx  0x%-8lx  %s (%s)\n", i, kmod_info.reference_count, (uint64_t)kmod_info.address, kmod_info.size, kmod_info.name, kmod_info.version);
    }
end:
	return 0;
}
