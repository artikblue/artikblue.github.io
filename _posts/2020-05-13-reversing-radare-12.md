---
layout: post
title:  Reverse engineering 32 and 64 bits binaries with Radare2 - 13 (defines, unions and bitmaps)
tags: reversing c radare
image: '/images//radare2/radare2_13.png'
date: 2020-05-13 15:01:35 -0700
---

Today we are gonna get a bit low level. We'll review important stuff like unions bitmaps and defines, that are commonly used in progams that run inside small systems.

#### Unions

In the C languages, unions are special data structures that allow us to store different data types in the same memory location. We can define a union with many members, but only one member can contain a value at any given time. Unions provide an efficient way of using the same memory location for multiple-purpose. These structures are commonly seen in systems where little space is available for the program, think about embedded systems for example.

We'll start by reviewing this example:
```c
#include <stdio.h>


int main() {
    
union {
   char ichar; /* 1 byte */
   int num; /* 4 bytes */
} sample;

   int n1, n2;
    
    printf("Size of 'sample' union = %d \n", sizeof(sample));
    sample.num = 25;
    sample.ichar = 50;
    printf("%d", sample.num);
    

   getchar();
   getchar();
   return 0;
}
```
If we compile and run this program what we will see is the following:
```
$ ./union1
Size of 'sample' union = 4 
50
```
As you see, the union took the largest variable, the int in this case, for defining the size as 4 bytes can hold either an int or a char.

```
[0x7fb4c26cb090]> s main
[0x55b90da1b145]> pdf
            ; DATA XREF from entry0 @ 0x55b90da1b07d
┌ 80: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_4h @ rbp-0x4
│           0x55b90da1b145      55             push rbp
│           0x55b90da1b146      4889e5         mov rbp, rsp
│           0x55b90da1b149      4883ec10       sub rsp, 0x10
│           0x55b90da1b14d      be04000000     mov esi, 4
│           0x55b90da1b152      488d3dab0e00.  lea rdi, str.Size_of__sample__union____d ; 0x55b90da1c004 ; "Size of 'sample' union = %d \n"
│           0x55b90da1b159      b800000000     mov eax, 0
│           0x55b90da1b15e      e8cdfeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55b90da1b163      c745fc190000.  mov dword [var_4h], 0x19 ; 25
│           0x55b90da1b16a      c645fc32       mov byte [var_4h], 0x32 ; '2' ; 50
│           0x55b90da1b16e      8b45fc         mov eax, dword [var_4h]
│           0x55b90da1b171      89c6           mov esi, eax
│           0x55b90da1b173      488d3da80e00.  lea rdi, [0x55b90da1c022] ; "%d"
│           0x55b90da1b17a      b800000000     mov eax, 0
│           0x55b90da1b17f      e8acfeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55b90da1b184      e8b7feffff     call sym.imp.getchar    ; int getchar(void)
│           0x55b90da1b189      e8b2feffff     call sym.imp.getchar    ; int getchar(void)
│           0x55b90da1b18e      b800000000     mov eax, 0
│           0x55b90da1b193      c9             leave
└           0x55b90da1b194      c3             ret
[0x55b90da1b145]> 
```
This concept is very easy to understand when disasm'ing the code. At first, 0x19 = 25dec is  loaded in var_4h, then 0x32 = 50dec is loaded in the exact same place

So for the first load:
```
│           0x55b90da1b163      c745fc190000.  mov dword [var_4h], 0x19 ; 25
│           ;-- rip:
│           0x55b90da1b16a b    c645fc32       mov byte [var_4h], 0x32 ; '2' ; 50

[0x55b90da1b16a]> afvd
var var_4h = 0x7ffd1dd3133c = (qword)0x0da1b1a000000019
[0x55b90da1b16a]> 
```
Then for the second load
```
dc
[0x55b90da1b16e]> afvd
var var_4h = 0x7ffd1dd3133c = (qword)0x0da1b1a000000032
```
The same space gets updated with the new value, plain and simple.

Let's proceed with a final example on this:

```c
#include <stdio.h>


int main() {
    
union {
   char ichar; /* 1 byte */
   int num; /* 4 bytes */
   char arr[20];
} sample;

   int n1, n2;
    
    printf("Size of 'sample' union = %d \n", sizeof(sample));
    sample.num = 25;
    sample.ichar = 50;
    printf("value= %d \n", sample.num);
    strcpy(sample.arr,"hello world");
    printf("value= %s \n",sample.arr);
    sample.num = 65;
    printf("value= %s \n",sample.arr);


   getchar();
   getchar();
   return 0;
}
```
In this example, a char array has been added, so what will be the size now? Exactly, 20 bytes, but as we have space for an array here (arr = base addr) and also referenes to char and int's... I guess you already realized that weird stuff can happen here, let's see:

```
[0x55e376e55155]> pdf
            ; DATA XREF from entry0 @ 0x55e376e5508d
┌ 194: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_8h @ rbp-0x8
│           0x55e376e55155      55             push rbp
│           0x55e376e55156      4889e5         mov rbp, rsp
│           0x55e376e55159      4883ec20       sub rsp, 0x20
│           0x55e376e5515d      64488b042528.  mov rax, qword fs:[0x28]
│           0x55e376e55166      488945f8       mov qword [var_8h], rax
│           0x55e376e5516a      31c0           xor eax, eax
│           0x55e376e5516c      be14000000     mov esi, 0x14           ; 20
│           0x55e376e55171      488d3d8c0e00.  lea rdi, str.Size_of__sample__union____d ; 0x55e376e56004 ; "Size of 'sample' union = %d \n"
│           0x55e376e55178      b800000000     mov eax, 0
│           0x55e376e5517d      e8befeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55e376e55182      c745e0190000.  mov dword [var_20h], 0x19 ; 25
│           0x55e376e55189      c645e032       mov byte [var_20h], 0x32 ; '2' ; 50
│           0x55e376e5518d      8b45e0         mov eax, dword [var_20h]
│           0x55e376e55190      89c6           mov esi, eax
│           0x55e376e55192      488d3d890e00.  lea rdi, str.value___d  ; 0x55e376e56022 ; "value= %d \n"
│           0x55e376e55199      b800000000     mov eax, 0
│           0x55e376e5519e      e89dfeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55e376e551a3      488d45e0       lea rax, [var_20h]
│           0x55e376e551a7      48ba68656c6c.  movabs rdx, 0x6f77206f6c6c6568 ; 'hello wo'
│           0x55e376e551b1      488910         mov qword [rax], rdx
│           0x55e376e551b4      c74008726c64.  mov dword [rax + 8], 0x646c72 ; 'rld'
│                                                                      ; [0x646c72:4]=-1
│           0x55e376e551bb      488d45e0       lea rax, [var_20h]
│           0x55e376e551bf      4889c6         mov rsi, rax
│           0x55e376e551c2      488d3d650e00.  lea rdi, str.value___s  ; 0x55e376e5602e ; "value= %s \n"
│           0x55e376e551c9      b800000000     mov eax, 0
│           0x55e376e551ce      e86dfeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55e376e551d3      c745e0410000.  mov dword [var_20h], 0x41 ; 'A' ; 65
│           0x55e376e551da      488d45e0       lea rax, [var_20h]
│           0x55e376e551de      4889c6         mov rsi, rax
│           0x55e376e551e1      488d3d460e00.  lea rdi, str.value___s  ; 0x55e376e5602e ; "value= %s \n"
│           0x55e376e551e8      b800000000     mov eax, 0
│           0x55e376e551ed      e84efeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55e376e551f2      e859feffff     call sym.imp.getchar    ; int getchar(void)
│           0x55e376e551f7      e854feffff     call sym.imp.getchar    ; int getchar(void)
│           0x55e376e551fc      b800000000     mov eax, 0
│           0x55e376e55201      488b4df8       mov rcx, qword [var_8h]
│           0x55e376e55205      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x55e376e5520e      7405           je 0x55e376e55215
│       │   0x55e376e55210      e81bfeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55e376e55215      c9             leave
└           0x55e376e55216      c3             ret
[0x55e376e55155]> 
```
So at this point of the program:
```
│           ;-- rip:
│           0x55e376e551a7 b    48ba68656c6c.  movabs rdx, 0x6f77206f6c6c6568 ; 'hello wo'
│           0x55e376e551b1      488910         mov qword [rax], rdx
│           0x55e376e551b4      c74008726c64.  mov dword [rax + 8], 0x646c72 ; 'rld'

var var_20h = 0x7fffe11a8270 = (qword)0x000055e300000032
```
The union will hold the value of 0x32 at this point, then movabs and mov will be used to store the string "Hello world" inside the union, let's see:
```
│                                                                      ; [0x646c72:4]=-1
│           ;-- rip:
│           0x55e376e551bb b    488d45e0       lea rax, [var_20h]
│           0x55e376e551bf      4889c6         mov rsi, rax


var var_20h = 0x7fffe11a8270 = (qword)0x6f77206f6c6c6568
[0x55e376e551bb]> pxw @ 0x7fffe11a8270
0x7fffe11a8270  0x6c6c6568 0x6f77206f 0x00646c72 0x000055e3  hello world..U..
0x7fffe11a8280  0xe11a8370 0x00007fff 0xd33c3600 0x910f1334  p........6<.4...
``` 
If we just want to print the string pointed by that mem addr we can just use ps for that
```
[0x7fffe11a8280]> ps @ 0x7fffe11a8270
hello world
[0x7fffe11a8280]> 
```
But then we have this thing over here:
```
│           0x55e376e551d3      c745e0410000.  mov dword [var_20h], 0x41 ; 'A' ; 65
│           0x55e376e551da      488d45e0       lea rax, [var_20h]
│           0x55e376e551de      4889c6         mov rsi, rax
```
0x000000041, gets moved to the base addr of the array, what do you think it will happen? One can guess that the first letter of the array 'H' will turn to 'A' and the string will look like 'Aello World', but a full mov has been used instead of a mov byte... let's see:
```
[0x55e376e551da]> pxw @ 0x7fffe11a8270
0x7fffe11a8270  0x00000041 0x6f77206f 0x00646c72 0x000055e3  A...o world..U..

[0x55e376e551da]> ps @ 0x7fffe11a8270
A
```
So mov 0x41 has placed this exact value at the base addr of the array: 0x00000041, as you see 0x41 contains 0x00, the NULL terminator that indicates the END of a string...so the program understands that the string ends with the A, the rest of the characters are just garbage and don't come into play anymore... eventhough they are still in memory!

Getting this concept well is key when doing reversing and exploiting, as for example, sending a null character can break our shellcode and make our exploit unusable.

How would you solve that to make the full string valid again? (patch the program!) Take it as an exercise.


#### Bitfields

Bit fields are a bit similar to unions hehe. Jokes aside, bit fields are easy to understand. With bitfields we can define structs of variables of a specific size of N bits, making thus the needed space much less. For example, a typical struct of two ints will have a size of 8 bytes, maybe those ints serve as true/false flags, so only 1 and 0 are needed for that why do we need to keep space for numbers as large as 0xFFFFFFF? btw only one bit is needed, bitfields come very handy here. 

Let's start by looking at this example:
```c
#include <stdio.h>
#include <string.h>

/* define simple structure */
struct {
   unsigned int widthValidated;
   unsigned int heightValidated;
} status1;

/* define a structure with bit fields */
struct {
   unsigned int widthValidated : 1;
   unsigned int heightValidated : 1;
} status2;
 
int main( ) {
   printf( "Memory size occupied by status1 : %d\n", sizeof(status1));
   printf( "Memory size occupied by status2 : %d\n", sizeof(status2));
   return 0;
}
```

```
$ ./bitfield1 
Memory size occupied by status1 : 8
Memory size occupied by status2 : 4
```
As you can see, the second struct is half the space of the first. Now that you get the idea, let's reverse the following one:
```c
#include <stdio.h>
#include <string.h>

struct {
   unsigned int age : 3;
} Age;
#include <stdio.h>
#include <string.h>

struct {
   unsigned int age : 3;
} Age;

int main( ) {

   Age.age = 4;
   printf( "Sizeof( Age ) : %d\n", sizeof(Age) );
   printf( "Age.age : %d\n", Age.age );

   Age.age = 7;
   printf( "Age.age : %d\n", Age.age );

   Age.age = 8;
   printf( "Age.age : %d\n", Age.age );

   return 0;
}
```
The disasm will look like:

```
[0x564052630135]> pdf
            ; DATA XREF from entry0 @ 0x56405263006d
┌ 180: int main (int argc, char **argv, char **envp);
│           0x564052630135      55             push rbp
│           0x564052630136      4889e5         mov rbp, rsp
│           0x564052630139      0fb605d42e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=0
│           0x564052630140      83e0f8         and eax, 0xfffffff8     ; 4294967288
│           0x564052630143      83c804         or eax, 4
│           0x564052630146      8805c82e0000   mov byte [0x564052633014], al ; [0x564052633014:1]=0
│           0x56405263014c      be04000000     mov esi, 4
│           0x564052630151      488d3dac0e00.  lea rdi, str.Sizeof__Age___:__d ; 0x564052631004 ; "Sizeof( Age ) : %d\n"
│           0x564052630158      b800000000     mov eax, 0
│           0x56405263015d      e8cefeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x564052630162      0fb605ab2e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=0
│           0x564052630169      83e007         and eax, 7
│           0x56405263016c      0fb6c0         movzx eax, al
│           0x56405263016f      89c6           mov esi, eax
│           0x564052630171      488d3da00e00.  lea rdi, str.Age.age_:__d ; 0x564052631018 ; "Age.age : %d\n"
│           0x564052630178      b800000000     mov eax, 0
│           0x56405263017d      e8aefeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x564052630182      0fb6058b2e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=0
│           0x564052630189      83c807         or eax, 7
│           0x56405263018c      8805822e0000   mov byte [0x564052633014], al ; [0x564052633014:1]=0
│           0x564052630192      0fb6057b2e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=0
│           0x564052630199      83e007         and eax, 7
│           0x56405263019c      0fb6c0         movzx eax, al
│           0x56405263019f      89c6           mov esi, eax
│           0x5640526301a1      488d3d700e00.  lea rdi, str.Age.age_:__d ; 0x564052631018 ; "Age.age : %d\n"
│           0x5640526301a8      b800000000     mov eax, 0
│           0x5640526301ad      e87efeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5640526301b2      0fb6055b2e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=0
│           0x5640526301b9      83e0f8         and eax, 0xfffffff8     ; 4294967288
│           0x5640526301bc      8805522e0000   mov byte [0x564052633014], al ; [0x564052633014:1]=0
│           0x5640526301c2      0fb6054b2e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=0
│           0x5640526301c9      83e007         and eax, 7
│           0x5640526301cc      0fb6c0         movzx eax, al
│           0x5640526301cf      89c6           mov esi, eax
│           0x5640526301d1      488d3d400e00.  lea rdi, str.Age.age_:__d ; 0x564052631018 ; "Age.age : %d\n"
│           0x5640526301d8      b800000000     mov eax, 0
│           0x5640526301dd      e84efeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5640526301e2      b800000000     mov eax, 0
│           0x5640526301e7      5d             pop rbp
└           0x5640526301e8      c3             ret
```
Let's look now at the first chink of code, where 4 is loaded into the age variable. We can see the program first zeroing eax then doing an and with 0xfffffff8, why is that? 0xfffffff8 = 0b11111111111111111111111111111000 (remember that we are using 3 bits only...?) if we do AND 0b0000000.... all zeros with that we will automatically get rid of every useless bit. Then an OR with 4 will leave us with a 4 in eax as or takes the greater value.
```
│           0x564052630139      0fb605d42e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=0
│           0x564052630140 b    83e0f8         and eax, 0xfffffff8     ; 4294967288
│           0x564052630143      83c804         or eax, 4

[0x564052630146]> dr
rax = 0x00000004
```
Then the variable will be updated with a 4, later on, when we are loading a 7, we do another or:
```
│           0x564052630182 b    0fb6058b2e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=4
│           0x564052630189      83c807         or eax, 7
│           0x56405263018c      8805822e0000   mov byte [0x564052633014], al ; [0x564052633014:1]=4

[0x564052630182]> ds
[0x564052630189]> dr eax
0x00000004
[0x564052630189]> ds
[0x56405263018c]> dr eax
0x00000007
```
As 4 or 7 returns 7 (it returns the higher number), the value is updated to 7. This is a very interesting compiler trick, as everything here is calculated, instead of moved, so the operation runs faster here and less space is needed.

But what happens at the end of this program, we we try to load 8dec insidde the bitmap?
```
│           0x5640526301b2      0fb6055b2e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=4
│           0x5640526301b9      83e0f8         and eax, 0xfffffff8     ; 4294967288
│           0x5640526301bc      8805522e0000   mov byte [0x564052633014], al ; [0x564052633014:1]=4
│           0x5640526301c2      0fb6054b2e00.  movzx eax, byte [0x564052633014] ; [0x564052633014:1]=4
│           0x5640526301c9      83e007         and eax, 7
│           0x5640526301cc      0fb6c0         movzx eax, al
│           0x5640526301cf      89c6           mov esi, eax
│           0x5640526301d1      488d3d400e00.  lea rdi, str.Age.age_:__d ; 0x564052631018 ; "Age.age : %d\n"
│           0x5640526301d8      b800000000     mov eax, 0
```
If you compute that yourself, age here will be updated to zero instead of 8, why is that? 8dec = 1000bin and we are only playing with 3 bits here so those 3 bits will be extracted from 8 = 000bin that is 0 and thus the compiler will understand that what do we want to do here is to load a 0 inside age, nothing more. Note that entering an 8 or a 2323 or whatever in our code won't matter at the end, as the machine will eventually translate everything to binary and compute from there.



#### Defines

We are about to reach the end of this first part of the course. In C, the #define directive allows the definition of macros within your source code. These macro definitions allow constant values to be declared for use throughout your code.

Macro definitions are not variables and cannot be changed by your program code like variables.

This stack overflow answer is very clear on the topic: https://stackoverflow.com/questions/4024318/why-do-most-c-developers-use-define-instead-of-const
```c
#include <stdio.h>
 
#define SUM(x,y) x+y
#define MAX 10
 
int main() {
   int n1, n2;
 
   printf("VAL 1 = ");
   scanf("%d", &n1);
 
   printf("VAL 2 = ");
   scanf("%d", &n2);
 
   printf("SUM = %d\n", SUM(n1,n2));
   
   if(SUM(n1,n2)>MAX){
        printf("> MAX\n");      
   }
   getchar();
   getchar();
   return 0;
}
```
Let's peek inside
```
[0x55817740f175]> pdf
            ; DATA XREF from entry0 @ 0x55817740f0ad
┌ 194: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           0x55817740f175      55             push rbp
│           0x55817740f176      4889e5         mov rbp, rsp
│           0x55817740f179      4883ec10       sub rsp, 0x10
│           0x55817740f17d      64488b042528.  mov rax, qword fs:[0x28]
│           0x55817740f186      488945f8       mov qword [var_8h], rax
│           0x55817740f18a      31c0           xor eax, eax
│           0x55817740f18c      488d3d710e00.  lea rdi, str.VAL_1      ; 0x558177410004 ; "VAL 1 = "
│           0x55817740f193      b800000000     mov eax, 0
│           0x55817740f198      e8b3feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55817740f19d      488d45f0       lea rax, [var_10h]
│           0x55817740f1a1      4889c6         mov rsi, rax
│           0x55817740f1a4      488d3d620e00.  lea rdi, [0x55817741000d] ; "%d"
│           0x55817740f1ab      b800000000     mov eax, 0
│           0x55817740f1b0      e8bbfeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x55817740f1b5      488d3d540e00.  lea rdi, str.VAL_2      ; 0x558177410010 ; "VAL 2 = "
│           0x55817740f1bc      b800000000     mov eax, 0
│           0x55817740f1c1      e88afeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55817740f1c6      488d45f4       lea rax, [var_ch]
│           0x55817740f1ca      4889c6         mov rsi, rax
│           0x55817740f1cd      488d3d390e00.  lea rdi, [0x55817741000d] ; "%d"
│           0x55817740f1d4      b800000000     mov eax, 0
│           0x55817740f1d9      e892feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x55817740f1de      8b55f0         mov edx, dword [var_10h]
│           0x55817740f1e1      8b45f4         mov eax, dword [var_ch]
│           0x55817740f1e4      01d0           add eax, edx
│           0x55817740f1e6      89c6           mov esi, eax
│           0x55817740f1e8      488d3d2a0e00.  lea rdi, str.SUM____d   ; 0x558177410019 ; "SUM = %d\n"
│           0x55817740f1ef      b800000000     mov eax, 0
│           0x55817740f1f4      e857feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55817740f1f9      8b55f0         mov edx, dword [var_10h]
│           0x55817740f1fc      8b45f4         mov eax, dword [var_ch]
│           0x55817740f1ff      01d0           add eax, edx
│           0x55817740f201      83f80a         cmp eax, 0xa            ; 10
│       ┌─< 0x55817740f204      7e0c           jle 0x55817740f212
│       │   0x55817740f206      488d3d160e00.  lea rdi, str.MAX        ; 0x558177410023 ; "> MAX"
│       │   0x55817740f20d      e81efeffff     call sym.imp.puts       ; int puts(const char *s)
│       └─> 0x55817740f212      e849feffff     call sym.imp.getchar    ; int getchar(void)
│           0x55817740f217      e844feffff     call sym.imp.getchar    ; int getchar(void)
│           0x55817740f21c      b800000000     mov eax, 0
│           0x55817740f221      488b4df8       mov rcx, qword [var_8h]
│           0x55817740f225      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x55817740f22e      7405           je 0x55817740f235
│       │   0x55817740f230      e80bfeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55817740f235      c9             leave
└           0x55817740f236      c3             ret
[0x55817740f175]> 
```
There is no actual need to debug the code. As you can see, defines are just guidelines for the compiler, the compiler will insert the equiv of that operation wherever it is called, at the end the add will be done the same way there, no function will be called, just an asm add:
```
│           0x55817740f1de      8b55f0         mov edx, dword [var_10h]
│           0x55817740f1e1      8b45f4         mov eax, dword [var_ch]
│           0x55817740f1e4      01d0           add eax, edx
│           0x55817740f1e6      89c6           mov esi, eax
│           0x55817740f1e8      488d3d2a0e00.  lea rdi, str.SUM____d   ; 0x558177410019 ; "SUM = %d\n"
```
Same thing with the constant, a 0xA will be inserted wherever MAX is referenced
```
│           0x55817740f1ff      01d0           add eax, edx
│           0x55817740f201      83f80a         cmp eax, 0xa            ; 10
│       ┌─< 0x55817740f204      7e0c           jle 0x55817740f212
```
Another way to work with compiler macros is to include code from other files but, I won't go deep into that because no special stuff is seen in the disasm...Try it yourself.

And we are done with the very basic course. From here, I will introduce some crackmes to you as exam/practise and then we'll jump into the next part of the course, I'll move to more advanced concepts, such as pipes, processes(forks), threads and sockets clearly separating Windows and Unix code, as some stuff like sockets works slightly different in those different operating systems. We'll also go through some nice stuff in r2 that is still left to be shown like the powerful ESIL.