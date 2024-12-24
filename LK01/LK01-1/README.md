## Holstein - v1
### ret2user
- swapgs: Return to user space
- swap từ kernel space qua user space
- stack page guard

### kROP
- enable SMEP 
- Sau khi ROP có thể trở về user bằng cách đổi các segment register và swap về user hoặc add rsp để kernel chạy tiếp và tự trờ về user space (cần debug và fix thêm, mới chỉ test ở pwn.college)

### KPTI
- enable KPTI --> khi còn ở page của kernel giờ sẽ không đọc được dữ liệu từ page của user --> vẫn return được về user nhưng sẽ segfault
- swapgs_restore_regs_and_return_to_usermode

### KASLR
- leak từ module_read
