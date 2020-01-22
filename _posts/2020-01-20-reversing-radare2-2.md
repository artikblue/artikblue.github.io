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

##### The code
Let's start with this simple example. The following example-program, declares four variables, regarding to the numeric variables the first one represents an int, second one represents a float and the third one a double then we also have a char 'a'. At the end those values are added and the result is printed. We will see how the first variable gets directly stored in a (general purpose) register, the second one gets stored in memory too but in another place and the third one works the same with the exception that it needs 2 times the space of the second (double)
~~~
#include <stdio.h>

int main() {
  char ab ='a';
  int a = 3;
  float b = 4.5;
  double c = 5.25;
  float sum;
  
  sum = a+b+c;

  printf("The sum of a, b, and c is %f.", sum);
  return 0;
}
~~~
As always, we can compile the code by using gcc, no mistery.
##### The binary
We open the binary and then we analyze its content, aaa should work fine.
~~~
 -- sudo make me a pancake
[0x08048310]> aaa
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
[0x08048310]> 
~~~
As we compiled the binary using GCC, we can identify some "typical" functions related to the initialization of the program.
~~~
[0x08048310]> afl
0x08048310    1 33           entry0
0x080482f0    1 6            sym.imp.__libc_start_main
0x08048350    4 43           sym.deregister_tm_clones
0x08048380    4 53           sym.register_tm_clones
0x080483c0    3 30           entry.fini0
0x080483e0    4 43   -> 40   entry.init0
0x080484f0    1 2            sym.__libc_csu_fini
0x08048340    1 4            sym.__x86.get_pc_thunk.bx
0x080484f4    1 20           sym._fini
0x08048490    4 93           sym.__libc_csu_init
0x0804840b    1 123          main
0x080482e0    1 6            sym.imp.printf
0x080482ac    3 35           sym._init
[0x08048310]> 
~~~
The only interesting function here is the "main" one as it clearly belongs to the "main" function of the program. From here we can also identify that "printf" is used in the program.
~~~
[0x08048310]> sf main
[0x0804840b]> pdf
            ; DATA XREF from entry0 @ 0x8048327
┌ 123: int main (int32_t arg_4h, char **argv, char **envp);
│           ; var char var_1dh @ ebp-0x1d
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_4h @ esp+0x4c
│           0x0804840b      8d4c2404       lea ecx, [arg_4h]
│           0x0804840f      83e4f0         and esp, 0xfffffff0
│           0x08048412      ff71fc         push dword [ecx - 4]
│           0x08048415      55             push ebp
│           0x08048416      89e5           mov ebp, esp
│           0x08048418      51             push ecx
│           0x08048419      83ec34         sub esp, 0x34
│           0x0804841c      c645e361       mov byte [var_1dh], 0x61    ; 'a' ; 97
│           0x08048420      c745e4030000.  mov dword [var_1ch], 3
│           0x08048427      d9054c850408   fld dword [0x804854c]
│           0x0804842d      d95de8         fstp dword [ebp - 0x18]
│           0x08048430      dd0550850408   fld qword [0x8048550]
│           0x08048436      dd5df0         fstp qword [ebp - 0x10]
│           0x08048439      d9ee           fldz
│           0x0804843b      d95dec         fstp dword [ebp - 0x14]
│           0x0804843e      db45e4         fild dword [var_1ch]
│           0x08048441      d845e8         fadd dword [ebp - 0x18]
│           0x08048444      dc45f0         fadd qword [ebp - 0x10]
│           0x08048447      d95dec         fstp dword [ebp - 0x14]
│           0x0804844a      d945ec         fld dword [ebp - 0x14]
│           0x0804844d      83ec04         sub esp, 4
│           0x08048450      8d6424f8       lea esp, [esp - 8]
│           0x08048454      dd1c24         fstp qword [esp]
│           0x08048457      6810850408     push str.The_sum_of_a__b__and_c_is__f. ; 0x8048510 ; "The sum of a, b, and c is %f." ; const char *format
│           0x0804845c      e87ffeffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08048461      83c410         add esp, 0x10
│           0x08048464      0fbe45e3       movsx eax, byte [var_1dh]
│           0x08048468      83ec08         sub esp, 8
│           0x0804846b      50             push eax
│           0x0804846c      682e850408     push str.The_value_of_char_ab_is__c. ; 0x804852e ; "The value of char ab is %c." ; const char *format
│           0x08048471      e86afeffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08048476      83c410         add esp, 0x10
│           0x08048479      b800000000     mov eax, 0
│           0x0804847e      8b4dfc         mov ecx, dword [var_4h]
│           0x08048481      c9             leave
│           0x08048482      8d61fc         lea esp, [ecx - 4]
└           0x08048485      c3             ret
[0x0804840b]> 

~~~
As we look through the main code of the program we see some new instructions here, like fstp, fild, fadd and so forth by pure deduction we could state that those may be related to "floating point operations" as we use float and double here. We can also identify how the print function is called, we see some parameters being pushed onto the stack.  

As we are dealing with variables here, one of the things we may want to do is to see how radare2 identifies variables and maybe give them a nice name. We can doo this by using afv.
~~~
[0x0804840b]> afv
arg int32_t arg_4h @ esp+0x4c
var char var_1dh @ ebp-0x1d
var int32_t var_1ch @ ebp-0x1c
var int32_t var_4h @ ebp-0x4
[0x0804840b]> 
~~~
As we clearly identify a char with radare2 (var char var_1...) we can rename that variable to char
~~~
[0x0804840b]> afvn  char1 var_1dh
[0x0804840b]> afvn
char1
var_1ch
var_4h
arg_4h
[0x0804840b]> 
~~~
That char variable is interesting. When using char variables, what really happens internally is that those chars are hex encoded. In hex, 'a' corresponds to 61 in the ascii table. In our example we can simply see how the program uses mov to move the 0x61 byte to the position of the variable.
~~~
0x0804841c      c645e361       mov byte [var_1dh], 0x61    ; 'a' ; 97
0x08048420      c745e4030000.  mov dword [var_1ch], 3
~~~
Now that we have the char variable identified, and we should already be able to identify the int variable as well let's look at how the program deals with floating point variables.  

The best way to inspect that is by running the program in debug mode. In radare2 we can open a program in debug mode by using the -d option.  

In debug mode we can use commands such as "db memaddress" to set a breakpoint, "dc" to continue the execution flow to that/those breakpoint(s) and "dt" to run the current instruction and move to the next one right after.  

In our program we can set some interesting points before the fldz, flstp and such.
~~~
[0x0804840b]> db 0x08048427
[0x0804840b]> db 0x0804842d
[0x0804840b]> db 0x08048430
[0x0804840b]> dc
hit breakpoint at: 8048427
[0x08048427]> 
~~~
After we hit our first breakpoint we move to:
~~~
│           0x08048420      c745e4030000.  mov dword [var_1ch], 3
│           0x08048427      d9054c850408   fld dword [0x804854c]
│           0x0804842d      d95de8         fstp dword [ebp - 0x18]
~~~
We can identify that the 3 value has been moved to var_1ch and then some strange instruction is executed "fld dword". The fld instruction loads a 32 bit, 64 bit, or 80 bit floating point value onto the stack. This instruction converts 32 and 64 bit operand to an 80 bit extended precision value before pushing the value onto the floating point stack. So if we inspect what value is fld picking up for loading we will see something like:
~~~
[0x08048427]> px 32 @ 0x804854c
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0804854c  0000 9040 0000 0000 0000 1540 011b 033b  ...@.......@...;
0x0804855c  2800 0000 0400 0000 78fd ffff 4400 0000  (.......x...D...
[0x08048427]> 
~~~
" 0000 9040 0000 0000 0000 ".We can now try to inspect the contents of that position in memory which clearly corresponds to a variable
~~~
[0x08048430]> px @ ebp-0x18
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xbfe7a7e0  0000 9040 a4a8 e7bf aca8 e7bf b184 0408  ...@............
0xbfe7a7f0  dc93 f6b7 10a8 e7bf 0000 0000 37f6 dcb7  ............7...
0xbfe7a800  0090 f6b7 0090 f6b7 0000 0000 37f6 dcb7  ............7...
~~~
We can make the output a little bit more nice and human readable (for our case) by adding w and thus running pxw when w comes from word (two bytes)
~~~
[0x08048430]> pxw @ ebp-0x18
0xbfe7a7e0  0x40900000 0xbfe7a8a4 0xbfe7a8ac 0x080484b1  ...@............
0xbfe7a7f0  0xb7f693dc 0xbfe7a810 0x00000000 0xb7dcf637  ............7...
~~~
"0x40900000" must be the value. But that value gives us few information, at least in this format. As we suspect that this number represents a floating point encoded number, we can try to use the "rax2" tool to read it. 
~~~
[0xbfe7a7f0]> rax2  Fx40900000
4.500000f
~~~
And we can clearly see how this number corresponds to the value of our first floating point variable.  

We can do this exact same thing with the second variable, I will leave it up to you, you will find the value of 5.25, but as its a "double" value, instead of one word, we will have a size of 32.  
  
So finally, we can see how those parameters are pusshed to the stack. The string "The sum of..." is pushed directly to the stack by just doing "push" and the "sum" variable is inserted in to the stack by using the fstp instruction. The FST instruction copies the value in the ST(0) register to the destination operand, which can be a memory location or another register in the FPU register stack. When storing the value in memory, the value is converted to single- or double-real format.
~~~
|           0x08048447      d95dec         fstp dword [ebp - 0x14]
│           0x0804844a      d945ec         fld dword [ebp - 0x14]
│           0x0804844d      83ec04         sub esp, 4
│           0x08048450      8d6424f8       lea esp, [esp - 8]
│           0x08048454      dd1c24         fstp qword [esp]
│           0x08048457      6810850408     push str.The_sum_of_a__b__and_c_is__f. ; 0x8048510 ; "The sum of a, b, and c is %f." ; const char *format
│           0x0804845c      e87ffeffff     call sym.imp.printf         ; int printf(const char *format)
~~~
We see how the "sum" value comes from ebp-0x14 as a result of the previous operation:
~~~
[0x08048444]> pxw @ ebp-0x14
0xbf8e0ba4  0x00000000 0x00000000 0x40150000 0xb7f573dc  ...........@.s..
~~~
And it clearly corresponds to the actual result:
~~~
[0x0804844d]> rax2 Fx414c0000
12.750000f (as float)
~~~
And then it appears on the stack along with the address that points to the string to be printed
~~~
[0x0804845c]> pxw @ esp
0xbf8e0b70  0x08048510 0x00000000 0x40298000 0xb7f711b0  ..........)@....
0xbf8e0b80  0x00008000 0xb7f57000 0xb7f55244 0xb7dbd0ec  .....p..DR......
0xbf8e0b90  0x00000001 0x00000000 0x61dd3a50 0x00000003  ........P:.a....
~~~
*note that little endian is used here and 0x4029800000000000 = 12.75 as double = sum
#### Conditional structures

##### The code 

~~~
#include <stdio.h>
int main() {
    signed int number;
    printf("Enter an integer: ");
    scanf("%d", &number);
    if (number > 0) {
        printf("You entered %d.\n", number);
    }
    else{
                printf("You entered a negative number %d.\n", number);
        }
    printf("The if statement is easy.");
    return 0;

~~~

##### The binary


~~~
[0x080484bb]> pdf
            ; DATA XREF from entry0 @ 0x80483d7
┌ 159: int main (int argc, char **argv, char **envp);
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_4h @ esp+0x34
│           0x080484bb      8d4c2404       lea ecx, [arg_4h]
│           0x080484bf      83e4f0         and esp, 0xfffffff0
│           0x080484c2      ff71fc         push dword [ecx - 4]
│           0x080484c5      55             push ebp
│           0x080484c6      89e5           mov ebp, esp
│           0x080484c8      51             push ecx
│           0x080484c9      83ec14         sub esp, 0x14
│           0x080484cc      65a114000000   mov eax, dword gs:[0x14]
│           0x080484d2      8945f4         mov dword [var_ch], eax
│           0x080484d5      31c0           xor eax, eax
│           0x080484d7      83ec0c         sub esp, 0xc
│           0x080484da      68e0850408     push str.Enter_an_integer:  ; 0x80485e0 ; "Enter an integer: "
│           0x080484df      e88cfeffff     call sym.imp.printf         ; int printf(const char *format)
│           0x080484e4      83c410         add esp, 0x10
│           0x080484e7      83ec08         sub esp, 8
│           0x080484ea      8d45f0         lea eax, [var_10h]
│           0x080484ed      50             push eax
│           0x080484ee      68f3850408     push 0x80485f3
│           0x080484f3      e8a8feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x080484f8      83c410         add esp, 0x10
│           0x080484fb      8b45f0         mov eax, dword [var_10h]
│           0x080484fe      85c0           test eax, eax
│       ┌─< 0x08048500      7e16           jle 0x8048518
│       │   0x08048502      8b45f0         mov eax, dword [var_10h]
│       │   0x08048505      83ec08         sub esp, 8
│       │   0x08048508      50             push eax
│       │   0x08048509      68f6850408     push str.You_entered__d.    ; 0x80485f6 ; "You entered %d.\n"
│       │   0x0804850e      e85dfeffff     call sym.imp.printf         ; int printf(const char *format)
│       │   0x08048513      83c410         add esp, 0x10
│      ┌──< 0x08048516      eb14           jmp 0x804852c
│      │└─> 0x08048518      8b45f0         mov eax, dword [var_10h]
│      │    0x0804851b      83ec08         sub esp, 8
│      │    0x0804851e      50             push eax
│      │    0x0804851f      6808860408     push str.You_entered_a_negative_number__d. ; 0x8048608 ; "You entered a negative number %d.\n"
│      │    0x08048524      e847feffff     call sym.imp.printf         ; int printf(const char *format)
│      │    0x08048529      83c410         add esp, 0x10
│      │    ; CODE XREF from main @ 0x8048516
│      └──> 0x0804852c      83ec0c         sub esp, 0xc
│           0x0804852f      682b860408     push str.The_if_statement_is_easy. ; 0x804862b ; "The if statement is easy."
│           0x08048534      e837feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08048539      83c410         add esp, 0x10
│           0x0804853c      b800000000     mov eax, 0
│           0x08048541      8b55f4         mov edx, dword [var_ch]
│           0x08048544      653315140000.  xor edx, dword gs:[0x14]
│       ┌─< 0x0804854b      7405           je 0x8048552
│       │   0x0804854d      e82efeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x08048552      8b4dfc         mov ecx, dword [var_4h]
│           0x08048555      c9             leave
│           0x08048556      8d61fc         lea esp, [ecx - 4]
└           0x08048559      c3             ret
~~~

~~~
│           0x080484df      e88cfeffff     call sym.imp.printf         ; int printf(const char *format)
│           0x080484e4      83c410         add esp, 0x10
│           0x080484e7      83ec08         sub esp, 8
│           0x080484ea b    8d45f0         lea eax, [input]
│           0x080484ed      50             push eax
│           0x080484ee      68f3850408     push 0x80485f3
│           0x080484f3 b    e8a8feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x080484f8 b    83c410         add esp, 0x10
│           0x080484fb      8b45f0         mov eax, dword [input]
│           0x080484fe      85c0           test eax, eax
~~~

~~~
[0x080484ed]> dr
eax = 0xbfa9a688
ebx = 0x00000000
ecx = 0x0910b01a
edx = 0xb7f0c870
esi = 0xb7f0b000
edi = 0xb7f0b000
esp = 0xbfa9a678
ebp = 0xbfa9a698
eip = 0x080484ed
eflags = 0x00000296
oeax = 0xffffffff
~~~

~~~
[0x080484ed]> dc
hit breakpoint at: 80484f3
[0x080484f3]> pxr @ esp
0xbfa9a670 0x080485f3  .... @esp (/home/lab/c_examples/bin/ifelse) (.rodata) program R X 'and eax, 0x6f590064' 'ifelse' (%d)
0xbfa9a674 0xbfa9a688  .... ([stack]) stack R W 0xbfa9a74c -->  ([stack]) stack R W 0xbfa9c288 -->  ([stack]) stack R W 0x5f474458 (XDG_VTNR=7) -->  ascii ('X')
0xbfa9a678 0xb7d87a50  Pz.. (/lib/i386-linux-gnu/libc-2.23.so) library R X 'add ebx, 0x1835b0' 'libc-2.23.so'
0xbfa9a67c 0x080485ab  .... (/home/lab/c_examples/bin/ifelse) (.text) sym.__libc_csu_init program R X 'add edi, 1' 'ifelse'
0xbfa9a680 0x00000001  .... 1 (.comment)
0xbfa9a684 0xbfa9a744  D... ([stack]) stack R W 0xbfa9c27f -->  ([stack]) stack R W 0x66692f2e (./ifelse) -->  ascii ('.')
~~~

~~~
[0x080484f3]> dc
Enter an integer: 10
hit breakpoint at: 80484f8
[0x080484f8]> 
~~~

~~~
[0x080484f8]> dr
eax = 0x00000001
ebx = 0x00000000
ecx = 0x00000001
edx = 0xb7f0c87c
esi = 0xb7f0b000
edi = 0xb7f0b000
esp = 0xbfa9a670
ebp = 0xbfa9a698
eip = 0x080484f8
eflags = 0x00000246
oeax = 0xffffffff
[0x080484f8]> 
~~~

~~~
[0x080484f8]> pxw @ 0xbfa9a688
0xbfa9a688  0x0000000a 0x630f3300 0xb7f0b3dc 0xbfa9a6b0  .....3.c........
~~~

~~~
[0x080484f8]> rax2 0xa
10
~~~

~~~
[0x080484f8]> 


│           0x080484f8 b    83c410         add esp, 0x10
│           0x080484fb      8b45f0         mov eax, dword [input]
│           0x080484fe      85c0           test eax, eax
│       ┌─< 0x08048500      7e16           jle 0x8048518
│       │   0x08048502      8b45f0         mov eax, dword [input]
│       │   0x08048505      83ec08         sub esp, 8
~~~

~~~
[0x08048500]> dr 1
cf = 0x00000000
pf = 0x00000001
af = 0x00000000
zf = 0x00000000
sf = 0x00000000
tf = 0x00000000
if = 0x00000001
df = 0x00000000
of = 0x00000000
~~~
The TEST instruction sets ZF and SF based on a logical AND between the operands, and clears OF.

"Less than or equal" is defined as: ZF=1 or SF != OF
~~~
[0x080484bb]> db 0x08048500
[0x080484bb]> dc
Enter an integer: -20
hit breakpoint at: 8048500
[0x08048500]> dr 1
cf = 0x00000000
pf = 0x00000000
af = 0x00000000
zf = 0x00000000
sf = 0x00000001
tf = 0x00000000
if = 0x00000001
df = 0x00000000
of = 0x00000000
[0x08048500]> 


[0x080484bb]> db 0x08048500
[0x080484bb]> dc
Enter an integer: 20
hit breakpoint at: 8048500
[0x08048500]> dr 1
cf = 0x00000000
pf = 0x00000001
af = 0x00000000
zf = 0x00000000
sf = 0x00000000
tf = 0x00000000
if = 0x00000001
df = 0x00000000
of = 0x00000000
[0x08048500]> 
~~~

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