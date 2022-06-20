---
layout: post
title: Reverse engineering 32 and 64 bits binaries with Radare2 - 5 (var types and casting)
tags: reversing c radare
image: images/radare2/radare2_6.png
date: 2020-05-01 15:01:35 -0700
---

Hi folks and welcome back to the most awesome reverse engineering with r2 post series 8) Today I'm going to drop some notes on very basic variable types you may encounter when reversing C code (and in general terms) and we'll review how casting is done at low level. It will be relatively quick.

![20min adventure](assets/images/20min.jpg)

Casting is a way we have to "convert" a variable of one kind to another kind. By the way, tutorialspoint makes it very easy to understand:

"Converting one datatype into another is known as type casting or, type-conversion. For example, if you want to store a 'long' value into a simple integer then you can type cast 'long' to 'int'. You can convert the values from one type to another explicitly using the cast operator as follows − (type_name) expression"

Let's review a simple example:
```C
# include <stdio.h>

main(){

 func();    
 getchar();
}

func(){

int val = 2;
float a = 5.25;

int b = (int)a;

printf ("%d\n", b);  

}
```

The disasm looks like this:
```
[0x55630491a6a4]> pdf
/ (fcn) sym.func 65
|   sym.func ();
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x55630491a693 (sym.main)
|           0x55630491a6a4      55             push rbp
|           0x55630491a6a5      4889e5         mov rbp, rsp
|           0x55630491a6a8      4883ec10       sub rsp, 0x10
|           0x55630491a6ac      c745f4020000.  mov dword [local_ch], 2
|           0x55630491a6b3      f30f1005bd00.  movss xmm0, dword [0x55630491a778] ; [0x55630491a778:4]=0x40a80000
|           0x55630491a6bb      f30f1145f8     movss dword [local_8h], xmm0
|           0x55630491a6c0      f30f1045f8     movss xmm0, dword [local_8h]
|           0x55630491a6c5      f30f2cc0       cvttss2si eax, xmm0
|           0x55630491a6c9      8945fc         mov dword [local_4h], eax
|           0x55630491a6cc      8b45fc         mov eax, dword [local_4h]
|           0x55630491a6cf      89c6           mov esi, eax
|           0x55630491a6d1      488d3d9c0000.  lea rdi, qword [0x55630491a774] ; "%d\n"
|           0x55630491a6d8      b800000000     mov eax, 0
|           0x55630491a6dd      e86efeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55630491a6e2      90             nop
|           0x55630491a6e3      c9             leave
\           0x55630491a6e4      c3             ret
[0x55630491a6a4]> 
```
At first sight, we can see some new instructions such as movss and the weird cvttss2si we never saw on the previous posts. Also new registers are being used: xmm0. In brief xmm registers that usually go from xmm0 to xmm7 are used to store floating point numbers, they have a size of 128 bits, as a float needs more space than an int. 

In a situation such as this, we generally have 2 options we can either try to interpret those instructions one by one and figure out what the program does or we can just set a breakpoint, for example, after xmm0 is stored to local_8h and inspect the content:

```
[0x5634635196a4]> pdf
/ (fcn) sym.func 65
|   sym.func ();
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x563463519693 (sym.main)
|           0x5634635196a4      55             push rbp
|           0x5634635196a5      4889e5         mov rbp, rsp
|           0x5634635196a8      4883ec10       sub rsp, 0x10
|           0x5634635196ac      c745f4020000.  mov dword [local_ch], 2
|           0x5634635196b3      f30f1005bd00.  movss xmm0, dword [0x563463519778] ; [0x563463519778:4]=0x40a80000
|           0x5634635196bb      f30f1145f8     movss dword [local_8h], xmm0
|           0x5634635196c0      f30f1045f8     movss xmm0, dword [local_8h]
|           ;-- rip:
|           0x5634635196c5 b    f30f2cc0       cvttss2si eax, xmm0
|           0x5634635196c9      8945fc         mov dword [local_4h], eax
|           0x5634635196cc      8b45fc         mov eax, dword [local_4h]
|           0x5634635196cf      89c6           mov esi, eax
|           0x5634635196d1      488d3d9c0000.  lea rdi, qword [0x563463519774] ; "%d\n"
|           0x5634635196d8      b800000000     mov eax, 0
|           0x5634635196dd      e86efeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5634635196e2      90             nop
|           0x5634635196e3      c9             leave
\           0x5634635196e4      c3             ret
[0x5634635196a4]> 

[0x5634635196a4]> pxw @ 0x563463519778
0x563463519778  0x40a80000 0x3b031b01 0x00000040 0x00000007  ...@...;@.......

[0x5634635196a4]> drt fpu
frip = 0x00000000
frdp = 0x00000000
st0 = 0x00000000
st1 = 0x00000000
st2 = 0x00000000
st3 = 0x00000000
st4 = 0x00000000
st5 = 0x00000000
st6 = 0x00000000
st7 = 0x00000000
xmm0h = 0x40a80000
xmm0l = 0x00000000
xmm1h = 0x31747361632f2e
xmm1l = 0x524f4c4f435f534c
xmm2h = 0xff00000000000000
xmm2l = 0x00000000
xmm3h = 0x0000ff00
xmm3l = 0x00000000
xmm4h = 0x2f2f2f2f2f2f2f2f
xmm4l = 0x2f2f2f2f2f2f2f2f
xmm5h = 0x00000000
xmm5l = 0x00000000
xmm6h = 0x00000000
xmm6l = 0x00000000
xmm7h = 0x00000000
xmm7l = 0x00000000
x64 = 0x00000000
[0x5634635196a4]> 
```
As we can see, at first local_ch is initialized with 2, thats an easy one it should be a simple int variable, then the content of 0x563463519778 is loaded into xmm0 register and that goes to the variable local_8h. If we inspect the contents of the xmm0 register by using drt, we'll see 0x40a80000, that corresponds to 5.25 in float. 

```
rax2 Fx40a80000
5.250000f
```
Radare2 can help us with that as it can auto detect variable types, at this point of the program if we do afta, we'll see how those change:
```
[0x558e5889c6a4]> afvt local_8h float
[0x558e5889c6a4]> pdf
/ (fcn) sym.func 65
|   sym.func ();
|           ; var int local_ch @ rbp-0xc
|           ; var float local_8h @ rbp-0x8
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x558e5889c693 (sym.main)
|           0x558e5889c6a4      55             push rbp
|           0x558e5889c6a5      4889e5         mov rbp, rsp
[...]
[0x558e5889c6a4]> 
```
And with afvt var type we can set the type of the variable ourselves. Regarding to the instructions used here:
```
|           0x5634635196b3      f30f1005bd00.  movss xmm0, dword [0x563463519778] ; [0x563463519778:4]=0x40a80000
|           0x5634635196bb      f30f1145f8     movss dword [local_8h], xmm0
|           0x5634635196c0      f30f1045f8     movss xmm0, dword [local_8h]
|           ;-- rip:
|           0x5634635196c5 b    f30f2cc0       cvttss2si eax, xmm0
```
Movss (move scalar single precision floating point value) moves a scalar single-precision floating-point value from the source operand (second operand) to the destination operand (first operand). The source and destination operands can be XMM registers or 32-bit memory locations. So that is basically used as the common mov but for floating point vals as those are bigger. Then cvttss2si (convert with truncation scalar single precision floating point value to integer) is what basically does the casting here, it truncates cuts the decimal part from the float and extracts and int, going from 5.25 to 5. The rest of the disasm should already be familiar to the reader :)

Let's now do another kind of casting, this time we'll go from character to integer.


```C
# include <stdio.h>

main(){

 func();    
 getchar();
}

func(){

char b = 'a';

int x = (int)b;
printf ("%d", x);
}
```
And if we look at the disasm...
```
[0x55b8bc8c96a4]> pdf
/ (fcn) sym.func 44
|   sym.func ();
|           ; var int local_5h @ rbp-0x5
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x55b8bc8c9693 (sym.main)
|           0x55b8bc8c96a4      55             push rbp
|           0x55b8bc8c96a5      4889e5         mov rbp, rsp
|           0x55b8bc8c96a8      4883ec10       sub rsp, 0x10
|           0x55b8bc8c96ac      c645fb61       mov byte [local_5h], 0x61 ; 'a' ; 97
|           0x55b8bc8c96b0      0fbe45fb       movsx eax, byte [local_5h]
|           0x55b8bc8c96b4      8945fc         mov dword [local_4h], eax
|           0x55b8bc8c96b7      8b45fc         mov eax, dword [local_4h]
|           0x55b8bc8c96ba      89c6           mov esi, eax
|           0x55b8bc8c96bc      488d3d910000.  lea rdi, qword [0x55b8bc8c9754] ; "%d"
|           0x55b8bc8c96c3      b800000000     mov eax, 0
|           0x55b8bc8c96c8      e883feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55b8bc8c96cd      90             nop
|           0x55b8bc8c96ce      c9             leave
\           0x55b8bc8c96cf      c3             ret
[0x55b8bc8c96a4]> 
```
This one is mega simple, the thing happens here:
```
|           0x55b8bc8c96ac      c645fb61       mov byte [local_5h], 0x61 ; 'a' ; 97
|           0x55b8bc8c96b0      0fbe45fb       movsx eax, byte [local_5h]
|           0x55b8bc8c96b4      8945fc         mov dword [local_4h], eax
|           0x55b8bc8c96b7      8b45fc         mov eax, dword [local_4h]
```
byte 0x61 (ascii a) is stored in local_5h, good that should mean char b = 'a', then it goes to EAX (we don't use rax, as the var is a single byte) and from there it goes to local_4h and that should mean int x = (int) b; then params are passed and printf is called, easy. movsx is used here as it moves with sign extension is it a common technique to use it when it comes to casting from int to char and from char to int (more info: https://stackoverflow.com/questions/7762214/assembly-converting-mov-movzx-and-movsx-to-c-code-no-inline-asm)

Let's finish this one with a last example


```C
# include <stdio.h>

main(){

 func();    
 getchar();
}

func(){
char b = 'a';

int x = (int)b;
printf ("%d\n", x);
printf ("%d\n", b);

}
```
As you can see, we start with the chracter 'a' we store it as both char and int using two variables and then we print both. The key thing to note here is that both of the times we pass the format string %d to printf, as %d is for printing the int value, we'll get 97 as the output both of the times! So 0x61 represents both 97 dec and ascii 'a' it is the same, the only diference here is that if we pretend to store an int we'll need two times the space of a char, that's all. The output format will depend on the format string in printf.

Let's see
```
[0x5570cc50c6a4]> pdf
/ (fcn) sym.func 67
|   sym.func ();
|           ; var int local_5h @ rbp-0x5
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x5570cc50c693 (sym.main)
|           0x5570cc50c6a4      55             push rbp
|           0x5570cc50c6a5      4889e5         mov rbp, rsp
|           0x5570cc50c6a8      4883ec10       sub rsp, 0x10
|           0x5570cc50c6ac      c645fb61       mov byte [local_5h], 0x61 ; 'a' ; 97
|           0x5570cc50c6b0      0fbe45fb       movsx eax, byte [local_5h]
|           0x5570cc50c6b4      8945fc         mov dword [local_4h], eax
|           0x5570cc50c6b7      8b45fc         mov eax, dword [local_4h]
|           0x5570cc50c6ba      89c6           mov esi, eax
|           0x5570cc50c6bc      488d3db10000.  lea rdi, qword [0x5570cc50c774] ; "%d\n"
|           0x5570cc50c6c3      b800000000     mov eax, 0
|           0x5570cc50c6c8      e883feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5570cc50c6cd      0fbe45fb       movsx eax, byte [local_5h]
|           0x5570cc50c6d1      89c6           mov esi, eax
|           0x5570cc50c6d3      488d3d9a0000.  lea rdi, qword [0x5570cc50c774] ; "%d\n"
|           0x5570cc50c6da      b800000000     mov eax, 0
|           0x5570cc50c6df      e86cfeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5570cc50c6e4      90             nop
|           0x5570cc50c6e5      c9             leave
\           0x5570cc50c6e6      c3             ret
[0x5570cc50c6a4]> 
[0x5570cc50c6a4]> afvd
var local_5h = 0x7ffce6d687eb  0xd688000000006161   aa......
var local_4h = 0x7ffce6d687ec  0xe6d6880000000061   a.......
[0x5570cc50c6a4]> dc
97
97
```
At the end it's all just a matter of interpretation

That was very short, on the 