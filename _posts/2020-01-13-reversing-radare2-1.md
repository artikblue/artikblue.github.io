---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 1"
author: artikblue
categories: [ reversing, course ]
tags: [reversing, c, radare]
image: assets/images/radare2/radare2_1.png
description: "Reverse engineering (C) 32 and 64 bits binaries with radare2."
---




~~~
lab@lab-VirtualBox:~$ radare2 c_examples/bin/hello_world 
 -- Use V! to enter into the visual panels mode (dwm style)
[0x08048310]> aaaa
[Cannot analyze at 0x08048300g with sym. and entry0 (aa)
[x] Analyze all flags starting with sym. and entry0 (aa)
[Cannot analyze at 0x08048300ac)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Finding function preludes
[x] Enable constraint types analysis for variables
[0x08048310]> 
~~~


~~~
[0x08048310]> afl
0x08048310    1 33           entry0
0x080482f0    1 6            sym.imp.__libc_start_main
0x08048350    4 43           sym.deregister_tm_clones
0x08048380    4 53           sym.register_tm_clones
0x080483c0    3 30           entry.fini0
0x080483e0    4 43   -> 40   entry.init0
0x080484a0    1 2            sym.__libc_csu_fini
0x08048340    1 4            sym.__x86.get_pc_thunk.bx
0x080484a4    1 20           sym._fini
0x08048440    4 93           sym.__libc_csu_init
0x0804840b    1 46           main
0x080482e0    1 6            sym.imp.printf
0x080482ac    3 35           sym._init
[0x08048310]> 
~~~

~~~
[0x08048310]> ii
[Imports]
nth                vaddr              bind   type              name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
577730550794551297 0xb6f9994600000000 FUNC   printf            
2                  0xb6f9994d00000000 NOTYPE __gmon_start__    
577730619514028035 0xb6f9994600000000 FUNC   __libc_start_main 
~~~


~~~
[0x08048310]> iI
arch     x86
baddr    0x8048000
binsz    6115
bintype  elf
bits     32
canary   false
class    ELF32
compiler GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609
crypto   false
endian   little
havecode true
intrp    /lib/ld-linux.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  Intel 80386
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true

[0x08048310]> 
~~~



~~~
[0x08048310]> iz
[Strings]
nth           paddr             vaddr       len size     section type          string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
5222680231936 0x80484c000000000 0xd00000000 14  34461128 ascii   Hello, World! bin.strings

[0x08048310]> 
~~~


~~~
[0x08048310]> sf main
[0x0804840b]> pdb
            ; DATA XREF from entry0 @ 0x8048327
┌ 46: int main (int32_t arg_4h, char **argv, char **envp);
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_4h @ esp+0x24
│           0x0804840b      8d4c2404       lea ecx, [arg_4h]
│           0x0804840f      83e4f0         and esp, 0xfffffff0
│           0x08048412      ff71fc         push dword [ecx - 4]
│           0x08048415      55             push ebp
│           0x08048416      89e5           mov ebp, esp
│           0x08048418      51             push ecx
│           0x08048419      83ec04         sub esp, 4
│           0x0804841c      83ec0c         sub esp, 0xc
│           0x0804841f      68c0840408     push str.Hello__World       ; 0x80484c0 ; "Hello, World!" ; const char *format
│           0x08048424      e8b7feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08048429      83c410         add esp, 0x10
│           0x0804842c      b800000000     mov eax, 0
│           0x08048431      8b4dfc         mov ecx, dword [var_4h]
│           0x08048434      c9             leave
│           0x08048435      8d61fc         lea esp, [ecx - 4]
└           0x08048438      c3             ret
[0x0804840b]> 
~~~


~~~
[0x00000540]> sf sym.main
[0x0000064a]> pdb
            ;-- main:
/ (fcn) sym.main 28
|   sym.main ();
|              ; DATA XREF from 0x0000055d (entry0)
|           0x0000064a      55             push rbp
|           0x0000064b      4889e5         mov rbp, rsp
|           0x0000064e      488d3d9f0000.  lea rdi, qword str.Hello__World ; 0x6f4 ; "Hello, World!" ; const char * format
|           0x00000655      b800000000     mov eax, 0
|           0x0000065a      e8c1feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0000065f      b800000000     mov eax, 0
|           0x00000664      5d             pop rbp
\           0x00000665      c3             ret
[0x0000064a]> 
~~~










