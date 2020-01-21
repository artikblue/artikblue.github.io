---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 2"
author: artikblue
categories: [ reversing, course ]
tags: [reversing, c, radare]
image: assets/images/radare2/radare2_2.png
description: "Reverse engineering (C) 32 and 64 bits binaries with radare2."
---
Welcome to this next part of the reverse engineering with radare2 course :) Today we are going to walk through some simple data structures such as variables, understand how basic conditional code structures work on the inside and we will also learn how to debug with radare2.

#### Variables

~~~
~~~

#### Conditional structures


~~~
~~~

#### Debugging


#### The 64 bit version

~~~
[0x7f584b7b9090]> sf main
[0x561302d2871a]> pdf
            ;-- main:
/ (fcn) main 161
|   main ();
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|              ; DATA XREF from 0x561302d2862d (entry0)
|           0x561302d2871a      55             push rbp
|           0x561302d2871b      4889e5         mov rbp, rsp
|           0x561302d2871e      4883ec10       sub rsp, 0x10
|           0x561302d28722      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x561302d2872b      488945f8       mov qword [local_8h], rax
|           0x561302d2872f      31c0           xor eax, eax
|           0x561302d28731      488d3d100100.  lea rdi, qword str.Enter_an_integer: ; 0x561302d28848 ; "Enter an integer: "
|           0x561302d28738      b800000000     mov eax, 0
|           0x561302d2873d      e89efeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x561302d28742      488d45f4       lea rax, qword [local_ch]
|           0x561302d28746      4889c6         mov rsi, rax
|           0x561302d28749      488d3d0b0100.  lea rdi, qword [0x561302d2885b] ; "%d"
|           0x561302d28750      b800000000     mov eax, 0
|           0x561302d28755      e896feffff     call sym.imp.__isoc99_scanf
|           0x561302d2875a      8b45f4         mov eax, dword [local_ch]
|           0x561302d2875d      85c0           test eax, eax
|       ,=< 0x561302d2875f      7e18           jle 0x561302d28779
|       |   0x561302d28761      8b45f4         mov eax, dword [local_ch]
|       |   0x561302d28764      89c6           mov esi, eax
|       |   0x561302d28766      488d3df10000.  lea rdi, qword str.You_entered__d. ; 0x561302d2885e ; "You entered %d.\n"
|       |   0x561302d2876d      b800000000     mov eax, 0
|       |   0x561302d28772      e869feffff     call sym.imp.printf     ; int printf(const char *format)
|      ,==< 0x561302d28777      eb16           jmp 0x561302d2878f
|      |`-> 0x561302d28779      8b45f4         mov eax, dword [local_ch]
|      |    0x561302d2877c      89c6           mov esi, eax
|      |    0x561302d2877e      488d3deb0000.  lea rdi, qword str.You_entered_a_negative_number__d. ; 0x561302d28870 ; "You entered a negative number %d.\n"
|      |    0x561302d28785      b800000000     mov eax, 0
|      |    0x561302d2878a      e851feffff     call sym.imp.printf     ; int printf(const char *format)
|      |       ; JMP XREF from 0x561302d28777 (main)
|      `--> 0x561302d2878f      488d3dfd0000.  lea rdi, qword str.The_if_statement_is_easy. ; 0x561302d28893 ; "The if statement is easy."
|           0x561302d28796      b800000000     mov eax, 0
|           0x561302d2879b      e840feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x561302d287a0      b800000000     mov eax, 0
|           0x561302d287a5      488b55f8       mov rdx, qword [local_8h]
|           0x561302d287a9      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x561302d287b2      7405           je 0x561302d287b9
|       |   0x561302d287b4      e817feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x561302d287b9      c9             leave
\           0x561302d287ba      c3             ret
[0x561302d2871a]> 
~~~