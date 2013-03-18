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
#include <mach-o/nlist.h>
#include <mach/mach_types.h>
#include <stddef.h>
#include <assert.h>
#include <sys/syscall.h>
#include <errno.h>
#include "distorm.h"
#include "mnemonics.h"

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

struct kernel_info
{
    uint64_t linkedit_fileoff;
    uint64_t linkedit_size;
    uint32_t symboltable_fileoff;
    uint32_t symboltable_nr_symbols;
    uint32_t stringtable_fileoff;
    uint32_t stringtable_size;
    void *linkedit_buf; // pointer to __LINKEDIT area
    uint64_t kaslr_slide;
};

// from xnu/bsd/sys/kas_info.h
#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR     (0)     /* returns uint64_t     */
#define KAS_INFO_MAX_SELECTOR           (1)
int kas_info(int selector, void *value, size_t *size);

// prototypes
void header(void);
void usage(void);
static int8_t readkmem(const int32_t fd, void *buffer, const uint64_t offset, const size_t size);
static kern_return_t process_kernel_mach_header(const void *kernel_buffer, struct kernel_info *kinfo);
static uint64_t read_target(uint8_t **targetBuffer, const char *target);
static mach_vm_address_t find_sloadedkexts(uint8_t *buffer, int32_t buffer_size, mach_vm_address_t offset_addr, mach_vm_address_t iorecursivelocklock);

#pragma mark Functions to read from kernel memory and file system

static int8_t
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

#pragma mark Header and help functions

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

#pragma mark Mach-O header and symbol related functions

/*
 * retrieve necessary mach-o header information from the kernel buffer
 * results stored in kernel_info structure
 */
static kern_return_t
process_kernel_mach_header(const void *kernel_buffer, struct kernel_info *kinfo)
{
    struct mach_header_64 *mh = (struct mach_header_64*)kernel_buffer;
    // test if it's a valid mach-o header (or appears to be)
    if (mh->magic != MH_MAGIC_64) return KERN_FAILURE;
    
    struct load_command *load_cmd = NULL;
    // point to the first load command
    char *load_cmd_addr = (char*)kernel_buffer + sizeof(struct mach_header_64);
    // iterate over all load cmds and retrieve required info to solve symbols
    // __LINKEDIT location and symbol/string table location
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                kinfo->linkedit_fileoff = seg_cmd->fileoff;
                kinfo->linkedit_size    = seg_cmd->filesize;
            }
        }
        // table information available at LC_SYMTAB command
        else if (load_cmd->cmd == LC_SYMTAB)
        {
            struct symtab_command *symtab_cmd = (struct symtab_command*)load_cmd;
            kinfo->symboltable_fileoff    = symtab_cmd->symoff;
            kinfo->symboltable_nr_symbols = symtab_cmd->nsyms;
            kinfo->stringtable_fileoff    = symtab_cmd->stroff;
            kinfo->stringtable_size       = symtab_cmd->strsize;
        }
        load_cmd_addr += load_cmd->cmdsize;
    }
    return KERN_SUCCESS;
}

/*
 * function to solve a kernel symbol
 */
mach_vm_address_t
solve_kernel_symbol(struct kernel_info *kinfo, char *symbol_to_solve)
{
    struct nlist_64 *nlist = NULL;
    
    if (kinfo == NULL || kinfo->linkedit_buf == NULL) return 0;
    
    for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++)
    {
        // symbols and strings offsets into LINKEDIT
        mach_vm_address_t symbol_off = kinfo->symboltable_fileoff - kinfo->linkedit_fileoff;
        mach_vm_address_t string_off = kinfo->stringtable_fileoff - kinfo->linkedit_fileoff;
        
        nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
        char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
        // find if symbol matches
        if (strncmp(symbol_to_solve, symbol_string, strlen(symbol_to_solve)) == 0)
        {
            printf("[INFO] found symbol %s at %p\n", symbol_to_solve, (void*)nlist->n_value);
            // the symbols are without kernel ASLR so we need to add it
            return (nlist->n_value + kinfo->kaslr_slide);
        }
    }
    // failure
    return 0;
}

/*
 * disassemble the function and lookup for sLoadedKexts
 * the format is like this:
 __text:FFFFFF80005F7090 55                                      push    rbp
 __text:FFFFFF80005F7091 48 89 E5                                mov     rbp, rsp
 __text:FFFFFF80005F7094 41 57                                   push    r15
 __text:FFFFFF80005F7096 41 56                                   push    r14
 __text:FFFFFF80005F7098 41 55                                   push    r13
 __text:FFFFFF80005F709A 41 54                                   push    r12
 __text:FFFFFF80005F709C 53                                      push    rbx
 __text:FFFFFF80005F709D 50                                      push    rax
 __text:FFFFFF80005F709E 89 FB                                   mov     ebx, edi
 __text:FFFFFF80005F70A0 48 8B 3D 59 61 2B 00                    mov     rdi, cs:qword_FFFFFF80008AD200
 __text:FFFFFF80005F70A7 E8 24 CA 02 00                          call    _IORecursiveLockLock
 __text:FFFFFF80005F70AC 48 8B 3D 75 61 2B 00                    mov     rdi, cs:sLoadedKexts
 */
static mach_vm_address_t
find_sloadedkexts(uint8_t *buffer, int32_t buffer_size, mach_vm_address_t offset_addr, mach_vm_address_t iorecursivelocklock)
{
#define MAX_INSTRUCTIONS 8192
    // allocate space for disassembly output
    _DInst *decodedInstructions = malloc(sizeof(_DInst) * MAX_INSTRUCTIONS);
    if (decodedInstructions == NULL)
    {
        printf("[ERROR] Decoded instructions allocation failed!\n");
        return -1;
    }
    unsigned int decodedInstructionsCount = 0;
	_DecodeResult res = 0;
    _CodeInfo ci;
    ci.dt = Decode64Bits;
    ci.features = DF_NONE;
    ci.codeLen = (int)buffer_size;
    ci.code = buffer;
    ci.codeOffset = offset_addr; // offset to function to be disassembled so diStorm gets addresses correct
    mach_vm_address_t next;
    while (1)
    {
        res = distorm_decompose(&ci, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR)
        {
            // Error handling...
            printf("[ERROR] Distorm failed to disassemble!\n");
            goto failure;
        }
        // iterate over the disassembly and lookup for CALL instructions
        for (int i = 0; i < decodedInstructionsCount; i++)
        {
            if (decodedInstructions[i].opcode == I_CALL)
            {
                // retrieve the target address and see if it matches the symbol we are looking for
                mach_vm_address_t rip_address = INSTRUCTION_GET_TARGET(&decodedInstructions[i]);
                if (rip_address == iorecursivelocklock)
                {
                    // get the sLoadedKexts from next instruction
                    mach_vm_address_t sloadedkexts = INSTRUCTION_GET_RIP_TARGET(&decodedInstructions[i+1]);
                    printf("[INFO] sLoadedKexts at %p\n", (void*)sloadedkexts);
                    return sloadedkexts;
                }
            }
        }
        if (res == DECRES_SUCCESS) break; // All instructions were decoded.
        else if (decodedInstructionsCount == 0) break;
        // sync the disassembly
        // the total number of bytes disassembly to previous last instruction
        next = decodedInstructions[decodedInstructionsCount-1].addr  - ci.codeOffset;
        // add points to the first byte so add instruction size to it
        next += decodedInstructions[decodedInstructionsCount-1].size;
        // update the CodeInfo struct with the synced data
        ci.code += next;
        ci.codeOffset += next;
        ci.codeLen -= next;
    }
    end:
        free(decodedInstructions);
    failure:
        free(decodedInstructions);
        return 0;
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

    // get info from the kernel at disk
    uint8_t *kernel_buffer = NULL;
    read_target(&kernel_buffer, "/mach_kernel");
    // get info we need to solve symbols from Mach-O header
    struct kernel_info kinfo = { 0 };
    if (process_kernel_mach_header((void*)kernel_buffer, &kinfo))
    {
        printf("[ERROR] Kernel Mach-O header processing failed!\n");
        exit(1);
    }
    // set a pointer to __LINKEDIT location in the kernel buffer
    kinfo.linkedit_buf = (void*)((char*)kernel_buffer + kinfo.linkedit_fileoff);
    kinfo.kaslr_slide = kaslr_slide;
    // solve the OSKext::lookupKextWithLoadTag symbol
    // and _IORecursiveLockLock, because sLoadedKexts is right after
    mach_vm_address_t loadtag_symbol = solve_kernel_symbol(&kinfo, LOOKUPKEXTWITHLOADTAG);
    mach_vm_address_t iorecursivelocklock = solve_kernel_symbol(&kinfo, "_IORecursiveLockLock");
    // disassemble and find the address of sLoadedKexts
    // it's easier to read it from memory than disk
    uint8_t loadtag_buffer[4096];
    readkmem(fd_kmem, loadtag_buffer, loadtag_symbol, 4096);
    mach_vm_address_t sLoadedKexts = find_sloadedkexts(loadtag_buffer, 4096, loadtag_symbol, iorecursivelocklock);
    
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
