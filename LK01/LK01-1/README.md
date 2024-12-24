## Holstein - v1
### ret2user
#### swapgs: Return to user space
- Khi ta ghi đè return address của module write và nhảy về địa chỉ ở userland thì các thanh ghi vẫn ở kernel land nên ta sẽ lưu trạng thái các thanh ghi ở chương trình userland và khôi phục lại sau khi nhảy về và tiếp tục gọi hàm win
- swap từ kernel space qua user space
#### stack page guard 
- Stack của kernel được mmaped theo đó là 1 page ở dưới để tránh việc buffer overflow khi ta đụng tới page này kernel sẽ panic
```c
static void exploit() {
    int fd = open("/dev/holstein", O_RDWR);

    char buf[0x1000];
    memset(buf, 'A', 0x1000);
    // *(unsigned long*)&buf[0x408] = (unsigned long)&escalate_privilege;
    
    write(fd, buf, 0x1000);
    close(fd);

    return;
}
```
[![image](https://hackmd.io/_uploads/rkrU7HOHyx.png)](https://github.com/hxzinh/pawnyable/blob/main.cpp/LK01/LK01-1/image/Screenshot%202024-12-24%20212200.png)


### kROP
- enable SMEP 
- Sau khi ROP có thể trở về user bằng cách đổi các segment register và swap về user hoặc add rsp để kernel chạy tiếp và tự trờ về user space (cần debug và fix thêm, mới chỉ test ở pwn.college)

### KPTI
- enable KPTI --> khi còn ở page của kernel giờ sẽ không đọc được dữ liệu từ page của user --> vẫn return được về user nhưng sẽ segfault
- swapgs_restore_regs_and_return_to_usermode

### KASLR
- leak từ module_read
