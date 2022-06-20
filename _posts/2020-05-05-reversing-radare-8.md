---
layout: post
title:  Reverse engineering 32 and 64 bits binaries with Radare2 - 9 (files; read, write, seek and some heaps :O)
tags: reversing c radare
image: '/images//radare2/radare2_9.png'
date: 2020-05-05 15:01:35 -0700
---
Heeello!

Today I want to talk you about file operations. File read and write operations are very important as most of the programs somehow work with files, for storing projects, for opening files for editing, for storing temp information, etc. Files are nothing more than information containers and can be represented as, for example, char arrays on memory.
#### Write to file
Let's start with this program:
```c
#include <stdio.h>
#include <string.h>
main(){
func();
getchar();
}


func()
{ 

   FILE* ftest;
 
    ftest = fopen("test.txt", "wt");
    fputs("This is a line\n", ftest);
    fputs("Another line", ftest);
    fputs(" that follows the second line\n", ftest);
    fclose(ftest);

}
```
To warm this thing up a little bit, let's inspect the program information:
```
[0x7f9d4a962090]> iI
arch     x86
baddr    0x55ea4645b000
binsz    6605
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      true
relocs   true
relro    full
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
[0x7f9d4a962090]> 
```
Then the strings
```
[0x7f9d4a962090]> iz
[Strings]
nth paddr      vaddr          len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x0000084b 0x55ea4645b84b 8   9    .rodata ascii test.txt
1   0x00000854 0x55ea4645b854 15  16   .rodata ascii This is a line\n
2   0x00000864 0x55ea4645b864 12  13   .rodata ascii Another line
3   0x00000878 0x55ea4645b878 30  31   .rodata ascii  that follows the second line\n

[0x7f9d4a962090]> 
```
And the imports:
```
[0x7f9d4a962090]> iS
[Sections]

nth paddr        size vaddr           vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000        0x0 ---- 
1   0x00000238   0x1c 0x55ea4645b238   0x1c -r-- .interp
2   0x00000254   0x20 0x55ea4645b254   0x20 -r-- .note.ABI_tag
3   0x00000274   0x24 0x55ea4645b274   0x24 -r-- .note.gnu.build_id
4   0x00000298   0x1c 0x55ea4645b298   0x1c -r-- .gnu.hash
5   0x000002b8   0xf0 0x55ea4645b2b8   0xf0 -r-- .dynsym
6   0x000003a8   0x99 0x55ea4645b3a8   0x99 -r-- .dynstr
7   0x00000442   0x14 0x55ea4645b442   0x14 -r-- .gnu.version
8   0x00000458   0x20 0x55ea4645b458   0x20 -r-- .gnu.version_r
9   0x00000478   0xc0 0x55ea4645b478   0xc0 -r-- .rela.dyn
10  0x00000538   0x60 0x55ea4645b538   0x60 -r-- .rela.plt
11  0x00000598   0x17 0x55ea4645b598   0x17 -r-x .init
12  0x000005b0   0x50 0x55ea4645b5b0   0x50 -r-x .plt
13  0x00000600    0x8 0x55ea4645b600    0x8 -r-x .plt.got
14  0x00000610  0x222 0x55ea4645b610  0x222 -r-x .text
15  0x00000834    0x9 0x55ea4645b834    0x9 -r-x .fini
16  0x00000840   0x57 0x55ea4645b840   0x57 -r-- .rodata
17  0x00000898   0x44 0x55ea4645b898   0x44 -r-- .eh_frame_hdr
18  0x000008e0  0x128 0x55ea4645b8e0  0x128 -r-- .eh_frame
19  0x00000da0    0x8 0x55ea4665bda0    0x8 -rw- .init_array
20  0x00000da8    0x8 0x55ea4665bda8    0x8 -rw- .fini_array
21  0x00000db0  0x1f0 0x55ea4665bdb0  0x1f0 -rw- .dynamic
22  0x00000fa0   0x60 0x55ea4665bfa0   0x60 -rw- .got
23  0x00001000   0x10 0x55ea4665c000   0x10 -rw- .data
24  0x00001010    0x0 0x55ea4665c010    0x8 -rw- .bss
25  0x00001010   0x29 0x00000000       0x29 ---- .comment
26  0x00001040  0x648 0x00000000      0x648 ---- .symtab
27  0x00001688  0x247 0x00000000      0x247 ---- .strtab
28  0x000018cf   0xfe 0x00000000       0xfe ---- .shstrtab
[0x7f9d4a962090]> 
```
Great, now we can disasm the principal function:
```
[0x55ea4645b734]> pdf
            ; CALL XREF from main @ 0x55ea4645b723
┌ 133: sym.func ();
│           ; var int64_t var_8h @ rbp-0x8
│           0x55ea4645b734      55             push rbp
│           0x55ea4645b735      4889e5         mov rbp, rsp
│           0x55ea4645b738      4883ec10       sub rsp, 0x10
│           0x55ea4645b73c      488d35050100.  lea rsi, [0x55ea4645b848] ; "wt"
│           0x55ea4645b743      488d3d010100.  lea rdi, str.test.txt   ; 0x55ea4645b84b ; "test.txt"
│           0x55ea4645b74a      e891feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           0x55ea4645b74f      488945f8       mov qword [var_8h], rax
│           0x55ea4645b753      488b45f8       mov rax, qword [var_8h]
│           0x55ea4645b757      4889c1         mov rcx, rax
│           0x55ea4645b75a      ba0f000000     mov edx, 0xf            ; 15
│           0x55ea4645b75f      be01000000     mov esi, 1
│           0x55ea4645b764      488d3de90000.  lea rdi, str.This_is_a_line ; 0x55ea4645b854 ; "This is a line\n"
│           0x55ea4645b76b      e880feffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x55ea4645b770      488b45f8       mov rax, qword [var_8h]
│           0x55ea4645b774      4889c1         mov rcx, rax
│           0x55ea4645b777      ba0c000000     mov edx, 0xc            ; 12
│           0x55ea4645b77c      be01000000     mov esi, 1
│           0x55ea4645b781      488d3ddc0000.  lea rdi, str.Another_line ; 0x55ea4645b864 ; "Another line"
│           0x55ea4645b788      e863feffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x55ea4645b78d      488b45f8       mov rax, qword [var_8h]
│           0x55ea4645b791      4889c1         mov rcx, rax
│           0x55ea4645b794      ba1e000000     mov edx, 0x1e           ; 30
│           0x55ea4645b799      be01000000     mov esi, 1
│           0x55ea4645b79e      488d3dd30000.  lea rdi, str.that_follows_the_second_line ; 0x55ea4645b878 ; " that follows the second line\n"
│           0x55ea4645b7a5      e846feffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x55ea4645b7aa      488b45f8       mov rax, qword [var_8h]
│           0x55ea4645b7ae      4889c7         mov rdi, rax
│           0x55ea4645b7b1      e80afeffff     call sym.imp.fclose     ; int fclose(FILE *stream)
│           0x55ea4645b7b6      90             nop
│           0x55ea4645b7b7      c9             leave
└           0x55ea4645b7b8      c3             ret
[0x55ea4645b734]> 
```
And after seeing the disasm, we can quickly see how simple this looks like. It basically calles fopen passing "text.txt" and "wt"(Open a text file, text.txt in this case, for writing. If the file already exists, its contents are destroyed.) fopen returns a file identifier through rax that is stored inside var_8h, then that pointer along with 0xf and "This is a line\n" is passed to fwrite. After that the same operation repeats another two times with different a string each time. Finally the reference to the file is passed to fclose and the function ends. By know you should perfectly know how parameters are passed to functions in the x64 world.


In C, we start working with files by opening them, using functions such as fopen. In brief, fopen() receives a file path and access permissions (read, write) and creates a FILE structure in the user heap containing a file descriptor fs and a fbuf of BLKSIZE size. As I assume that you already have some fundamental knowledge on operating systems I assume that you should know that a file descriptor in this case identifies the open file within the OS level (https://en.wikipedia.org/wiki/File_descriptor). It is important to remark though that what is returned by fopen is not a file descriptor, fopen returns a pointer to a FILE strruct. A file struct contains relevant information related to the file, to make things easy for us humans when working with files, we can use that FILE struct to work with many functions (https://www.studytonight.com/c/file-input-output.php). The thing is that, eventhough some fields like the file descriptor or fields related to buffers or size will be always present, the FILE struct or the way C deals with it may vary with the OS. Windows deals with that using calls to the win api, linux uses syscalls to the kernel some versions of gcc have slightly different details etc, so I wont' go into a lot of details related to that struct at least for now, I will try to teach you how to deal with that without having any previous knowledge on the struct format.


In general terms, what we must know here is that fopen returns a pointer that points to a place that contains relevant information related to the file (perhaps the content?) and that point is passed to functions that work with the file (for writting, reading, etc).

As we know, functions such as fopen make use of the heap, we'll inspect the heap with dmhg

We can place a breakpoint after the call and inspect the heap, it will look like:
```
│           0x55fe49a82743      488d3d010100.  lea rdi, str.test.txt   ; 0x55fe49a8284b ; "test.txt"
│           ;-- rip:
│           0x55fe49a8274a b    e891feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           0x55fe49a8274f b    488945f8       mov qword [var_8h], rax
│           0x55fe49a82753      488b45f8       mov rax, qword [var_8h]


[0x55fe49a8274a]> dmhg
No Heap section
```
But right after executing the fopen:
```
[0x55fe49a8274f]> dr
rax = 0x55fe4ada2260
rbx = 0x00000000
rcx = 0x00000063
rdx = 0x55fe49a8284a
r8 = 0x0000002c
r9 = 0x00000000
[...]
[0x55fe49a8274f]> dmhg
Heap Layout
┌────────────────────────────────────┐
│    Malloc chunk @ 0x55fe4ada2250   │
│ size: 0x230 status: allocated      │
└────────────────────────────────────┘
    v
    │
    └──┐
       │
   ┌───────────────────────────────┐
   │  Top chunk @ 0x55fe4ada2480   │
   └───────────────────────────────┘

[0x55fe49a8274f]> 

```
If we follow the execution right to the next hot spot, after the first call to fwrite, we'll see how more content gets added to the heap and that structure gets updated:
```
[0x55fe49a82770]> dmhg
Heap Layout
┌────────────────────────────────────┐
│    Malloc chunk @ 0x55fe4ada2250   │
│ size: 0x230 status: allocated      │
└────────────────────────────────────┘
    v
    │
    │
┌────────────────────────────────────┐
│    Malloc chunk @ 0x55fe4ada2480   │
│ size: 0x1010 status: allocated     │
└────────────────────────────────────┘
    v
    │
    └──┐
       │
   ┌───────────────────────────────┐
   │  Top chunk @ 0x55fe4ada3490   │
   └───────────────────────────────┘

[0x55fe49a82770]> pxw @ 0x55fe4ada2480
0x55fe4ada2480  0x33b4ad60 0x00007f00 0x00001011 0x00000000  `..3............
0x55fe4ada2490  0x73696854 0x20736920 0x696c2061 0x000a656e  This is a line..
0x55fe4ada24a0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada24b0  0x00000000 0x00000000 0x00000000 0x00000000  ................
```
It looks like we succesfully identified a potential buffer for our file. If we follow the execution through all the successive fwrites, we should see the content being written there, the heap space at the end of the execution will look like:
```
[0x55fe49a827aa]> pxw 900 @ 0x55fe4ada2250
0x55fe4ada2250  0x00000000 0x00000000 0x00000231 0x00000000  ........1.......
0x55fe4ada2260  0xfbad2c84 0x00000000 0x4ada2490 0x000055fe  .,.......$.J.U..
0x55fe4ada2270  0x4ada2490 0x000055fe 0x4ada2490 0x000055fe  .$.J.U...$.J.U..
0x55fe4ada2280  0x4ada2490 0x000055fe 0x4ada24c9 0x000055fe  .$.J.U...$.J.U..
0x55fe4ada2290  0x4ada3490 0x000055fe 0x4ada2490 0x000055fe  .4.J.U...$.J.U..
0x55fe4ada22a0  0x4ada3490 0x000055fe 0x00000000 0x00000000  .4.J.U..........
0x55fe4ada22b0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada22c0  0x00000000 0x00000000 0x33b4f680 0x00007f00  ...........3....
0x55fe4ada22d0  0x00000003 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada22e0  0x00000000 0x00000000 0x4ada2340 0x000055fe  ........@#.J.U..
0x55fe4ada22f0  0xffffffff 0xffffffff 0x00000000 0x00000000  ................
0x55fe4ada2300  0x4ada2350 0x000055fe 0x00000000 0x00000000  P#.J.U..........
0x55fe4ada2310  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2320  0xffffffff 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2330  0x00000000 0x00000000 0x33b4b2a0 0x00007f00  ...........3....
0x55fe4ada2340  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2350  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2360  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2370  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2380  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2390  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada23a0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada23b0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada23c0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada23d0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada23e0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada23f0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2400  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2410  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2420  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2430  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2440  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2450  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2460  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2470  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55fe4ada2480  0x33b4ad60 0x00007f00 0x00001011 0x00000000  `..3............
0x55fe4ada2490  0x73696854 0x20736920 0x696c2061 0x410a656e  This is a line.A
0x55fe4ada24a0  0x68746f6e 0x6c207265 0x20656e69 0x74616874  nother line that
0x55fe4ada24b0  0x6c6f6620 0x73776f6c 0x65687420 0x63657320   follows the sec
0x55fe4ada24c0  0x20646e6f 0x656e696c 0x0000000a 0x00000000  ond line........
```
Voilà, there is the content that goes written to the test.txt file. Was that useful in this case? Depends a lot on what you are looking for though...but you can be sure that inspecting the heap after suspicious functions get executed can lead to good findings.

#### Read from file
The last one was simple, let's now read from a file.
```c
#include <stdio.h>
#include <string.h>
main(){
funcion();
getchar();
}


funcion()
{ 

    FILE* ftest;
    char name[80] = "test.txt";
    char line[81];
 
    ftest = fopen(name, "rt");
 
    if (ftest == NULL)
    {
      printf("file not found!\n");
      exit(1);
    }
    fgets(line, 80, ftest);
    puts(line);
    fgets(line, 80, ftest);
    puts(line);
    fclose(ftest);


}
```
This time, the program initializes some space in memory, and opens text.txt with fopen. Fopen will return NULL if there is some error opening the file, so the program uses cmp and jne here to check if the file opens corrrectly or not, if there is some kind of error opening the file, the program calls exit(); and quits.

```
│           0x55d1449c31c9      48b874657374.  movabs rax, 0x7478742e74736574 ; 'test.txt'
│           0x55d1449c31d3      ba00000000     mov edx, 0
│           0x55d1449c31d8      48898550ffff.  mov qword [var_b0h], rax
│           0x55d1449c31df      48899558ffff.  mov qword [var_a8h], rdx
│           0x55d1449c31e6      48c78560ffff.  mov qword [var_a0h], 0
│           0x55d1449c31f1      48c78568ffff.  mov qword [var_98h], 0
│           0x55d1449c31fc      48c78570ffff.  mov qword [var_90h], 0
│           0x55d1449c3207      48c78578ffff.  mov qword [var_88h], 0
│           0x55d1449c3212      48c745800000.  mov qword [var_80h], 0
│           0x55d1449c321a      48c745880000.  mov qword [var_78h], 0
│           0x55d1449c3222      48c745900000.  mov qword [var_70h], 0
│           0x55d1449c322a      48c745980000.  mov qword [var_68h], 0
│           0x55d1449c3232      488d8550ffff.  lea rax, [var_b0h]
│           0x55d1449c3239      488d35c40d00.  lea rsi, [0x55d1449c4004] ; "rt"
│           0x55d1449c3240      4889c7         mov rdi, rax
│           0x55d1449c3243      e838feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           0x55d1449c3248 b    48898548ffff.  mov qword [var_b8h], rax
│           0x55d1449c324f      4883bd48ffff.  cmp qword [var_b8h], 0
│       ┌─< 0x55d1449c3257      7516           jne 0x55d1449c326f
```
As we see, the check is done here, if file is not found the program will prompt it and will exit with the code 1 (exit with error).
```
│       ┌─< 0x55d1449c3257      7516           jne 0x55d1449c326f
│       │   0x55d1449c3259      488d3da70d00.  lea rdi, str.file_not_found ; 0x55d1449c4007 ; "file not found!"
│       │   0x55d1449c3260      e8cbfdffff     call sym.imp.puts       ; int puts(const char *s)
│       │   0x55d1449c3265      bf01000000     mov edi, 1
│       │   0x55d1449c326a      e821feffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x55d1449c326f      488b9548ffff.  mov rdx, qword [var_b8h]
```
Then here we have the file pointer:
```
│           0x55d1449c3240      4889c7         mov rdi, rax
│           0x55d1449c3243      e838feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           ;-- rip:
│           0x55d1449c3248 b    48898548ffff.  mov qword [var_b8h], rax
│           0x55d1449c324f      4883bd48ffff.  cmp qword [var_b8h], 0
```
In memory:
```
[0x55d1449c3248]> dr
rax = 0x55d145eef260
rbx = 0x00000000
rcx = 0x00000005
rdx = 0x00000000
r8 = 0x00000000
r9 = 0x55d1449c4006
r10 = 0x00000000
r11 = 0x00000246
r12 = 0x55d1449c30b0
r13 = 0x7ffc18e1dc20
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x00000000
rdi = 0x55d1449c4005
rsp = 0x7ffc18e1da70
rbp = 0x7ffc18e1db30
rip = 0x55d1449c3248
rflags = 0x00000206
orax = 0xffffffffffffffff
[0x55d1449c3248]> pxw @ 0x55d145eef260
0x55d145eef260  0xfbad2488 0x00000000 0x00000000 0x00000000  .$..............
0x55d145eef270  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef280  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef290  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef2a0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef2b0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef2c0  0x00000000 0x00000000 0xf2630680 0x00007f28  ..........c.(...
0x55d145eef2d0  0x00000003 0x00000000 0x00000000 0x00000000  ................
0x55d145eef2e0  0x00000000 0x00000000 0x45eef340 0x000055d1  ........@..E.U..
0x55d145eef2f0  0xffffffff 0xffffffff 0x00000000 0x00000000  ................
0x55d145eef300  0x45eef350 0x000055d1 0x00000000 0x00000000  P..E.U..........
0x55d145eef310  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef320  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef330  0x00000000 0x00000000 0xf2631560 0x00007f28  ........`.c.(...
0x55d145eef340  0x00000000 0x00000000 0x00000000 0x00000000  ................
```
If we inspect the disasm we will see that fgets(line, 80, ftest); uses three parameters, it sends a pointer to a space in memory, a number and then a pointer to a FILE struct. So in this case, fgets will dump 80 characters (or everything untill the end of the file or a line jump is detected) to memory starting at the address pointed by the parameter we pass to it. We can debug the program and see it like this:
```
[0x55d1449c3282]> dr
rax = 0x7ffc18e1dad0
rbx = 0x00000000
rcx = 0x00000005
rdx = 0x55d145eef260
r8 = 0x00000000
r9 = 0x55d1449c4006
r10 = 0x00000000
r11 = 0x00000246
r12 = 0x55d1449c30b0
r13 = 0x7ffc18e1dc20
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x00000050
rdi = 0x7ffc18e1dad0
rsp = 0x7ffc18e1da70
rbp = 0x7ffc18e1db30
rip = 0x55d1449c3282
rflags = 0x00000206
orax = 0xffffffffffffffff
# BEFORE fgets() IS CALLED
[0x55d1449c3282]> pxw @ 0x7ffc18e1dad0
0x7ffc18e1dad0  0x00000000 0x00000000 0x00f0b5ff 0x00000000  ................
0x7ffc18e1dae0  0x000000c2 0x00000000 0x18e1db16 0x00007ffc  ................
0x7ffc18e1daf0  0x00000001 0x00000000 0xf2505b55 0x00007f28  ........U[P.(...
0x7ffc18e1db00  0x00000000 0x00000000 0x449c3325 0x000055d1  ........%3.D.U..
0x7ffc18e1db10  0xf2661b20 0x00007f28 0x00000000 0x00000000   .f.(...........
0x7ffc18e1db20  0x449c32e0 0x000055d1 0xb67e8600 0x110eefa4  .2.D.U....~.....
0x7ffc18e1db30  0x18e1db40 0x00007ffc 0x449c31a3 0x000055d1  @........1.D.U..
0x7ffc18e1db40  0x449c32e0 0x000055d1 0xf2471b6b 0x00007f28  .2.D.U..k.G.(...
0x7ffc18e1db50  0x00000000 0x00000000 0x18e1dc28 0x00007ffc  ........(.......
0x7ffc18e1db60  0x00040000 0x00000001 0x449c3195 0x000055d1  .........1.D.U..
0x7ffc18e1db70  0x00000000 0x00000000 0xdb1818b4 0xd55ddb37  ............7.].
0x7ffc18e1db80  0x449c30b0 0x000055d1 0x18e1dc20 0x00007ffc  .0.D.U.. .......
0x7ffc18e1db90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dba0  0x087818b4 0x810763cc 0x889e18b4 0x80aeb681  ..x..c..........
0x7ffc18e1dbb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dbc0  0x00000000 0x00000000 0x18e1dc38 0x00007ffc  ........8.......
[0x55d1449c3282]> dc
hit breakpoint at: 55d1449c3287
# AFTER fgets() IS CALLED
[0x55d1449c3287]> pxw @ 0x7ffc18e1dad0
0x7ffc18e1dad0  0x4c4c4548 0x4c45484f 0x45484f4c 0x0a4f4c4c  HELLOHELLOHELLO.
0x7ffc18e1dae0  0x00000000 0x00000000 0x18e1db16 0x00007ffc  ................
0x7ffc18e1daf0  0x00000001 0x00000000 0xf2505b55 0x00007f28  ........U[P.(...
0x7ffc18e1db00  0x00000000 0x00000000 0x449c3325 0x000055d1  ........%3.D.U..
0x7ffc18e1db10  0xf2661b20 0x00007f28 0x00000000 0x00000000   .f.(...........
0x7ffc18e1db20  0x449c32e0 0x000055d1 0xb67e8600 0x110eefa4  .2.D.U....~.....
0x7ffc18e1db30  0x18e1db40 0x00007ffc 0x449c31a3 0x000055d1  @........1.D.U..
0x7ffc18e1db40  0x449c32e0 0x000055d1 0xf2471b6b 0x00007f28  .2.D.U..k.G.(...
0x7ffc18e1db50  0x00000000 0x00000000 0x18e1dc28 0x00007ffc  ........(.......
0x7ffc18e1db60  0x00040000 0x00000001 0x449c3195 0x000055d1  .........1.D.U..
0x7ffc18e1db70  0x00000000 0x00000000 0xdb1818b4 0xd55ddb37  ............7.].
0x7ffc18e1db80  0x449c30b0 0x000055d1 0x18e1dc20 0x00007ffc  .0.D.U.. .......
0x7ffc18e1db90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dba0  0x087818b4 0x810763cc 0x889e18b4 0x80aeb681  ..x..c..........
0x7ffc18e1dbb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dbc0  0x00000000 0x00000000 0x18e1dc38 0x00007ffc  ........8.......
[0x55d1449c3287]> 
```
The second fgets does the same:
```

│           ;-- rip:
│           0x55d1449c32a6 b    e8b5fdffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
│           0x55d1449c32ab      488d45a0       lea rax, [var_60h]
│           0x55d1449c32af      4889c7         mov rdi, rax
│           0x55d1449c32b2      e879fdffff     call sym.imp.puts       ; int puts(const char *s)
│           0x55d1449c32b7      488b8548ffff.  mov rax, qword [var_b8h]
│           0x55d1449c32be      4889c7         mov rdi, rax
│           0x55d1449c32c1      e87afdffff     call sym.imp.fclose     ; int fclose(FILE *stream)
│           0x55d1449c32c6      90             nop
│           0x55d1449c32c7      488b4df8       mov rcx, qword [var_8h]
│           0x55d1449c32cb      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x55d1449c32d4      7405           je 0x55d1449c32db
│       │   0x55d1449c32d6      e875fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55d1449c32db      c9             leave
└           0x55d1449c32dc      c3             ret
[0x55d1449c32a6]> db 0x55d1449c32ab
[0x55d1449c32a6]> pxw @ 0x7ffc18e1dad0
0x7ffc18e1dad0  0x4c4c4548 0x4c45484f 0x45484f4c 0x0a4f4c4c  HELLOHELLOHELLO.
0x7ffc18e1dae0  0x00000000 0x00000000 0x18e1db16 0x00007ffc  ................
0x7ffc18e1daf0  0x00000001 0x00000000 0xf2505b55 0x00007f28  ........U[P.(...
0x7ffc18e1db00  0x00000000 0x00000000 0x449c3325 0x000055d1  ........%3.D.U..
0x7ffc18e1db10  0xf2661b20 0x00007f28 0x00000000 0x00000000   .f.(...........
0x7ffc18e1db20  0x449c32e0 0x000055d1 0xb67e8600 0x110eefa4  .2.D.U....~.....
0x7ffc18e1db30  0x18e1db40 0x00007ffc 0x449c31a3 0x000055d1  @........1.D.U..
0x7ffc18e1db40  0x449c32e0 0x000055d1 0xf2471b6b 0x00007f28  .2.D.U..k.G.(...
0x7ffc18e1db50  0x00000000 0x00000000 0x18e1dc28 0x00007ffc  ........(.......
0x7ffc18e1db60  0x00040000 0x00000001 0x449c3195 0x000055d1  .........1.D.U..
0x7ffc18e1db70  0x00000000 0x00000000 0xdb1818b4 0xd55ddb37  ............7.].
0x7ffc18e1db80  0x449c30b0 0x000055d1 0x18e1dc20 0x00007ffc  .0.D.U.. .......
0x7ffc18e1db90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dba0  0x087818b4 0x810763cc 0x889e18b4 0x80aeb681  ..x..c..........
0x7ffc18e1dbb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dbc0  0x00000000 0x00000000 0x18e1dc38 0x00007ffc  ........8.......
[0x55d1449c32a6]> dc
hit breakpoint at: 55d1449c32ab
[0x55d1449c32ab]> pxw @ 0x7ffc18e1dad0
0x7ffc18e1dad0  0x4c524f57 0x524f5744 0x4f57444c 0x0a444c52  WORLDWORLDWORLD.
0x7ffc18e1dae0  0x00000000 0x00000000 0x18e1db16 0x00007ffc  ................
0x7ffc18e1daf0  0x00000001 0x00000000 0xf2505b55 0x00007f28  ........U[P.(...
0x7ffc18e1db00  0x00000000 0x00000000 0x449c3325 0x000055d1  ........%3.D.U..
0x7ffc18e1db10  0xf2661b20 0x00007f28 0x00000000 0x00000000   .f.(...........
0x7ffc18e1db20  0x449c32e0 0x000055d1 0xb67e8600 0x110eefa4  .2.D.U....~.....
0x7ffc18e1db30  0x18e1db40 0x00007ffc 0x449c31a3 0x000055d1  @........1.D.U..
0x7ffc18e1db40  0x449c32e0 0x000055d1 0xf2471b6b 0x00007f28  .2.D.U..k.G.(...
0x7ffc18e1db50  0x00000000 0x00000000 0x18e1dc28 0x00007ffc  ........(.......
0x7ffc18e1db60  0x00040000 0x00000001 0x449c3195 0x000055d1  .........1.D.U..
0x7ffc18e1db70  0x00000000 0x00000000 0xdb1818b4 0xd55ddb37  ............7.].
0x7ffc18e1db80  0x449c30b0 0x000055d1 0x18e1dc20 0x00007ffc  .0.D.U.. .......
0x7ffc18e1db90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dba0  0x087818b4 0x810763cc 0x889e18b4 0x80aeb681  ..x..c..........
0x7ffc18e1dbb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dbc0  0x00000000 0x00000000 0x18e1dc38 0x00007ffc  ........8.......
[0x55d1449c32ab]> 
```
Note that as we are using the same char array (buffer) to read, the second fgets overwrites what was dumped on the first fgets. If we want keep both lines or do some more advanced read/write operations that may include changes of positions we can declare a bigger array and use fgets, seek and fgets, but wait what is seek? Let's see(k) it.


#### Seek in file and write
You may have noticed that as we call fgets multiple times we go forward in the file content, what if we want to go back? What if we want to directly jump at the end? fseek comes in very handy when dealing with these cases. Let's inspect the following program:
```c
#include <stdio.h>

int main () {
   FILE *fp;

   fp = fopen("fseek.txt","w+");
   fputs("This is a simple file, feel free to visit artik.blue to get fresh reversing stuff", fp);
  
   fseek( fp, 7, SEEK_SET );
   fputs(" C Programming Language", fp);
   fclose(fp);
   
   return(0);
}
```
As we can see, it first writes to a file, then seeks the pointer to the 7th position (think about a char array) then writes content there and then closes the file and exits. Inside radare:

```
[0x7f376be20090]> s main
[0x560d0969d165]> pdf
            ; DATA XREF from entry0 @ 0x560d0969d09d
┌ 130: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           0x560d0969d165      55             push rbp
│           0x560d0969d166      4889e5         mov rbp, rsp
│           0x560d0969d169      4883ec10       sub rsp, 0x10
│           0x560d0969d16d      488d35940e00.  lea rsi, [0x560d0969e008] ; "w+"
│           0x560d0969d174      488d3d900e00.  lea rdi, str.fseek.txt  ; 0x560d0969e00b ; "fseek.txt"
│           0x560d0969d17b      e8d0feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           0x560d0969d180      488945f8       mov qword [var_8h], rax
│           0x560d0969d184      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d188      4889c1         mov rcx, rax
│           0x560d0969d18b      ba51000000     mov edx, 0x51           ; 'Q' ; 81
│           0x560d0969d190      be01000000     mov esi, 1
│           0x560d0969d195      488d3d7c0e00.  lea rdi, str.This_is_a_simple_file__feel_free_to_visit_artik.blue_to_get_fresh_reversing_stuff ; 0x560d0969e018 ; "This is a simple file, feel free to visit artik.blue to get fresh reversing stuff"
│           0x560d0969d19c      e8bffeffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x560d0969d1a1      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1a5      ba00000000     mov edx, 0
│           0x560d0969d1aa      be07000000     mov esi, 7
│           0x560d0969d1af      4889c7         mov rdi, rax
│           0x560d0969d1b2      e889feffff     call sym.imp.fseek      ; int fseek(FILE *stream, long offset, int whence)
│           0x560d0969d1b7      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1bb      4889c1         mov rcx, rax
│           0x560d0969d1be      ba17000000     mov edx, 0x17           ; 23
│           0x560d0969d1c3      be01000000     mov esi, 1
│           0x560d0969d1c8      488d3d9b0e00.  lea rdi, str.C_Programming_Language ; 0x560d0969e06a ; " C Programming Language"
│           0x560d0969d1cf      e88cfeffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x560d0969d1d4      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1d8      4889c7         mov rdi, rax
│           0x560d0969d1db      e850feffff     call sym.imp.fclose     ; int fclose(FILE *stream)
│           0x560d0969d1e0      b800000000     mov eax, 0
│           0x560d0969d1e5      c9             leave
└           0x560d0969d1e6      c3             ret
[0x560d0969d165]> 
```

We see the same as before, except this time a new call comes in (seek). fseek receives 0x7 and the var that contains the FILE pointer, no surprises.

```
│           0x560d0969d1a1      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1a5      ba00000000     mov edx, 0
│           0x560d0969d1aa      be07000000     mov esi, 7
│           0x560d0969d1af      4889c7         mov rdi, rax
│           0x560d0969d1b2      e889feffff     call sym.imp.fseek      ; int fseek(FILE *stream, long offset, int whence)
│           0x560d0969d1b7      488b45f8       mov rax, qword [var_8h]
```
After fseek is called, no value is being taken, the system will now that it has to write starting at pos 7. Also note that no string sizes were declared on the C program, the good compiler calculates the size and inserts the parameter there for us (This is a simple file, feel free to visit artik.blue to get fresh reversing stuff = 81 characters 0x51 = dec 81).
```
│           0x560d0969d1b7      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1bb      4889c1         mov rcx, rax
│           0x560d0969d1be      ba17000000     mov edx, 0x17           ; 23
│           0x560d0969d1c3      be01000000     mov esi, 1
│           0x560d0969d1c8      488d3d9b0e00.  lea rdi, str.C_Programming_Language ; 0x560d0969e06a ; " C Programming Language"
│           0x560d0969d1cf      e88cfeffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x560d0969d1d4      488b45f8       mov rax, qword [var_8h]
```
So we already know how this works, nothing new here.


#### Read the whole file line by line

What if we just want to read the full file, line by line till the end. We keep reading lines using fgets until we reach EOF. Let's see:
```c
#include <stdio.h>

void main(){
char buffer[500];
FILE *fp;
int lineno = 0;
if ((fp = fopen("myinputfile.txt","r")) == NULL)
{
        printf("Could not open myinputfile.txt\n");
        exit(1);
}

while ( !feof(fp))
{
        // read in the line and make sure it was successful
        if (fgets(buffer,500,fp) != NULL)
        {
                printf("%d: %s",lineno++,buffer);
        }
}
}
``` 
This function should look familiar to us:

```
[0x55651c3ee195]> pdf
            ; DATA XREF from entry0 @ 0x55651c3ee0cd
┌ 209: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20ch @ rbp-0x20c
│           ; var int64_t var_208h @ rbp-0x208
│           ; var int64_t var_200h @ rbp-0x200
│           ; var int64_t var_8h @ rbp-0x8
│           0x55651c3ee195      55             push rbp
│           0x55651c3ee196      4889e5         mov rbp, rsp
│           0x55651c3ee199      4881ec100200.  sub rsp, 0x210
│           0x55651c3ee1a0      64488b042528.  mov rax, qword fs:[0x28]
│           0x55651c3ee1a9      488945f8       mov qword [var_8h], rax
│           0x55651c3ee1ad      31c0           xor eax, eax
│           0x55651c3ee1af      c785f4fdffff.  mov dword [var_20ch], 0
│           0x55651c3ee1b9      488d35480e00.  lea rsi, [0x55651c3ef008] ; "r"
│           0x55651c3ee1c0      488d3d430e00.  lea rdi, str.myinputfile.txt ; 0x55651c3ef00a ; "myinputfile.txt"
│           0x55651c3ee1c7      e8b4feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           0x55651c3ee1cc      488985f8fdff.  mov qword [var_208h], rax
│           0x55651c3ee1d3      4883bdf8fdff.  cmp qword [var_208h], 0
│       ┌─< 0x55651c3ee1db      755f           jne 0x55651c3ee23c
│       │   0x55651c3ee1dd      488d3d3c0e00.  lea rdi, str.Could_not_open_myinputfile.txt ; 0x55651c3ef020 ; "Could not open myinputfile.txt"
│       │   0x55651c3ee1e4      e847feffff     call sym.imp.puts       ; int puts(const char *s)
│       │   0x55651c3ee1e9      bf01000000     mov edi, 1
│       │   0x55651c3ee1ee      e89dfeffff     call sym.imp.exit       ; void exit(int status)
│      ┌──> 0x55651c3ee1f3      488b95f8fdff.  mov rdx, qword [var_208h]
│      ╎│   0x55651c3ee1fa      488d8500feff.  lea rax, [var_200h]
│      ╎│   0x55651c3ee201      bef4010000     mov esi, 0x1f4          ; 500
│      ╎│   0x55651c3ee206      4889c7         mov rdi, rax
│      ╎│   0x55651c3ee209      e852feffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
│      ╎│   0x55651c3ee20e      4885c0         test rax, rax
│     ┌───< 0x55651c3ee211      7429           je 0x55651c3ee23c
│     │╎│   0x55651c3ee213      8b85f4fdffff   mov eax, dword [var_20ch]
│     │╎│   0x55651c3ee219      8d5001         lea edx, [rax + 1]
│     │╎│   0x55651c3ee21c      8995f4fdffff   mov dword [var_20ch], edx
│     │╎│   0x55651c3ee222      488d9500feff.  lea rdx, [var_200h]
│     │╎│   0x55651c3ee229      89c6           mov esi, eax
│     │╎│   0x55651c3ee22b      488d3d0d0e00.  lea rdi, str.d:__s      ; 0x55651c3ef03f ; "%d: %s"
│     │╎│   0x55651c3ee232      b800000000     mov eax, 0
│     │╎│   0x55651c3ee237      e814feffff     call sym.imp.printf     ; int printf(const char *format)
│     └─└─> 0x55651c3ee23c      488b85f8fdff.  mov rax, qword [var_208h]
│      ╎    0x55651c3ee243      4889c7         mov rdi, rax
│      ╎    0x55651c3ee246      e825feffff     call sym.imp.feof       ; int feof(FILE *stream)
│      ╎    0x55651c3ee24b      85c0           test eax, eax
│      └──< 0x55651c3ee24d      74a4           je 0x55651c3ee1f3
│           0x55651c3ee24f      90             nop
│           0x55651c3ee250      488b45f8       mov rax, qword [var_8h]
│           0x55651c3ee254      644833042528.  xor rax, qword fs:[0x28]
│       ┌─< 0x55651c3ee25d      7405           je 0x55651c3ee264
│       │   0x55651c3ee25f      e8dcfdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55651c3ee264      c9             leave
└           0x55651c3ee265      c3             ret
[0x55651c3ee195]> 
```
As this may look a bit scary, we can use the r2dec decompiler! :) as we learned in the previous post:

```c
#include <stdint.h>
 
int32_t main (void) {
    int64_t var_20ch;
    int64_t var_208h;
    int64_t var_200h;
    int64_t var_8h;
    rax = *(fs:0x28);
    var_8h = *(fs:0x28);
    eax = 0;
    var_20ch = 0;
    rax = fopen ("myinputfile.txt", 0x55651c3ef008);
    var_208h = rax;
    if (var_208h != 0) {
        goto label_0;
    }
    puts ("Could not open myinputfile.txt");
    exit (1);
    do {
        rax = &var_200h;
        rax = fgets (rax, 0x1f4, var_208h);
        if (rax != 0) {
            eax = var_20ch;
            edx = rax + 1;
            var_20ch = edx;
            rdx = &var_200h;
            esi = eax;
            eax = 0;
            printf ("%d: %s");
        }
label_0:
        rax = var_208h;
        eax = feof (var_208h);
    } while (eax == 0);
    rax = var_8h;
    rax ^= *(fs:0x28);
    if (eax != 0) {
        stack_chk_fail ();
    }
    return rax;
}
```
So the key thing happens when comparing eax with 0 after calling feof.



that comparision happens here:
```
│      ╎    0x55651c3ee246      e825feffff     call sym.imp.feof       ; int feof(FILE *stream)
│      ╎    0x55651c3ee24b      85c0           test eax, eax
│      └──< 0x55651c3ee24d      74a4           je 0x55651c3ee1f3
```
In this case, feof will receive the FILE struct and will inspect the current position of the internal pointer, then it will determine if its the end of the file or not, easy!

As the rest of the program should be familiar to you I can proudly say that this post is over! See you on the next post of the course.















