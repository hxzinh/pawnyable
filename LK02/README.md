# Holstein - v2
## NULL Pointer Dereference
```
Note that the NULL Pointer Dereference used in this chapter cannot be exploited unless SMAP is disabled
```

### Spray cred_struct
| Region | Example Address Range | Purpose |
| -------- | -------- | -------- |
| Kernel Code/Data     | `0xffffffff80000000`     | Kernel text, static data     |
| Direct Mapping     | `0xffff888000000000`     | Maps all physical memory (heap)     |
| vmalloc/ioremap     | `0xffffc90000000000`     | Dynamically mapped memory     |
| Kernel Modules	     | `0xffffffffa0000000`     | Loadable kernel modules     |
| Userspace     | `0x0000000000000000`     | Userland processes |