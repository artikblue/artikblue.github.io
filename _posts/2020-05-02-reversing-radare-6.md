---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 6 (multi-dimensional arrays and structs)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_7.png
featured_image: assets/images/radare2/radare2_7.png
---

Hi there, I hope you are all good, as I promised here we have this next part of the reversing with radare2 mini course :)

Today we are still going to review some basic data structures you will encounter on many projects. According to my experience the key concepts on reverse engineering are identifying data structures, knowing basic operations and then it's all about the specific problem you want to solve, if you are on malware analysis then you'll have to focus on common malware tricks such as the use of specific syscalls or packing/encrypting techniques etc, if you are on exploit dev you'll focus more on specific protocols you want to analyse and fuzz, I've also known some people who do privacy analysis on apps and focus more on anything related to network protocols. You know, any specific area has its particularities and you'll but before going deep into any of those you'll need a solid base on common aspects such as data structures as everything is build on top of them.

On my last post we walked through some basic arrays (int and char) today we are going to go through more complex examples.

#### Multi dimensional arrays

Even the name sounds pretty cool those are very simple data structures also. An array can contain any element of whatever type inside, we can have arrays of ints, arrays of floats, of chars ...and we can have arrays of arrays. By the way, we can have arrays of arrays of arrays of [...].

Let's inspect the following code:

```c
# include <stdio.h>

main(){

 func();    
 getchar();
}

func(){
  int marks[2][10] = 
     { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
       11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

 
  printf("Mark related to third student on first group %d",
    marks[0][2]);
  printf("Mark related to third student on second group %d",
    marks[1][2]);

}
```
As you can see, we declare an int array of 2 dimensions and we initialize it with some values. Whats interesting here is that we initialize the two arrays one right after the other! It may look like we only have one big array of 20 vals instead of two arrays of 10 vals one "on top(?)" of the other. If you think about it, it makes all the sense, is there any other way to do it? At the end, the program will have to store those values (two arrays) in memory and they are part of the same "structure"  so it makes all the sense to allocate them together one after the other by the way doing it differently  won't make much sense. 



Let's see how it works internally:

```
[0x55af6f3ae714]> pdf
/ (fcn) sym.func 230
|   sym.func ();
|           ; var int local_60h @ rbp-0x60
|           ; var int local_5ch @ rbp-0x5c
|           ; var int local_58h @ rbp-0x58
|           ; var int local_54h @ rbp-0x54
|           ; var int local_50h @ rbp-0x50
|           ; var int local_4ch @ rbp-0x4c
|           ; var int local_48h @ rbp-0x48
|           ; var int local_44h @ rbp-0x44
|           ; var int local_40h @ rbp-0x40
|           ; var int local_3ch @ rbp-0x3c
|           ; var int local_38h @ rbp-0x38
|           ; var int local_34h @ rbp-0x34
|           ; var int local_30h @ rbp-0x30
|           ; var int local_2ch @ rbp-0x2c
|           ; var int local_28h @ rbp-0x28
|           ; var int local_24h @ rbp-0x24
|           ; var int local_20h @ rbp-0x20
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_18h @ rbp-0x18
|           ; var int local_14h @ rbp-0x14
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x55af6f3ae703 (sym.main)
|           0x55af6f3ae714      55             push rbp
|           0x55af6f3ae715      4889e5         mov rbp, rsp
|           0x55af6f3ae718      4883ec60       sub rsp, 0x60           ; '`'
|           0x55af6f3ae71c      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x55af6f3ae725      488945f8       mov qword [local_8h], rax
|           0x55af6f3ae729      31c0           xor eax, eax
|           0x55af6f3ae72b      c745a0010000.  mov dword [local_60h], 1
|           0x55af6f3ae732      c745a4020000.  mov dword [local_5ch], 2
|           0x55af6f3ae739      c745a8030000.  mov dword [local_58h], 3
|           0x55af6f3ae740      c745ac040000.  mov dword [local_54h], 4
|           0x55af6f3ae747      c745b0050000.  mov dword [local_50h], 5
|           0x55af6f3ae74e      c745b4060000.  mov dword [local_4ch], 6
|           0x55af6f3ae755      c745b8070000.  mov dword [local_48h], 7
|           0x55af6f3ae75c      c745bc080000.  mov dword [local_44h], 8
|           0x55af6f3ae763      c745c0090000.  mov dword [local_40h], 9
|           0x55af6f3ae76a      c745c40a0000.  mov dword [local_3ch], 0xa
|           0x55af6f3ae771      c745c80b0000.  mov dword [local_38h], 0xb ; 11
|           0x55af6f3ae778      c745cc0c0000.  mov dword [local_34h], 0xc ; 12
|           0x55af6f3ae77f      c745d00d0000.  mov dword [local_30h], 0xd ; 13
|           0x55af6f3ae786      c745d40e0000.  mov dword [local_2ch], 0xe ; 14
|           0x55af6f3ae78d      c745d80f0000.  mov dword [local_28h], 0xf ; 15
|           0x55af6f3ae794      c745dc100000.  mov dword [local_24h], 0x10 ; 16
|           0x55af6f3ae79b      c745e0110000.  mov dword [local_20h], 0x11 ; 17
|           0x55af6f3ae7a2      c745e4120000.  mov dword [local_1ch], 0x12 ; 18
|           0x55af6f3ae7a9      c745e8130000.  mov dword [local_18h], 0x13 ; 19
|           0x55af6f3ae7b0      c745ec140000.  mov dword [local_14h], 0x14 ; 20
|           0x55af6f3ae7b7      8b45a8         mov eax, dword [local_58h]
|           0x55af6f3ae7ba      89c6           mov esi, eax
|           0x55af6f3ae7bc      488d3dc50000.  lea rdi, qword str.Mark_related_to_third_student_on_first_group__d ; 0x55af6f3ae888 ; "Mark related to third student on first group %d"
|           0x55af6f3ae7c3      b800000000     mov eax, 0
|           0x55af6f3ae7c8      e8f3fdffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55af6f3ae7cd      8b45d0         mov eax, dword [local_30h]
|           0x55af6f3ae7d0      89c6           mov esi, eax
|           0x55af6f3ae7d2      488d3ddf0000.  lea rdi, qword str.Mark_related_to_third_student_on_second_group__d ; 0x55af6f3ae8b8 ; "Mark related to third student on second group %d"
|           0x55af6f3ae7d9      b800000000     mov eax, 0
|           0x55af6f3ae7de      e8ddfdffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55af6f3ae7e3      90             nop
|           0x55af6f3ae7e4      488b55f8       mov rdx, qword [local_8h]
|           0x55af6f3ae7e8      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x55af6f3ae7f1      7405           je 0x55af6f3ae7f8
|       |   0x55af6f3ae7f3      e8b8fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x55af6f3ae7f8      c9             leave
\           0x55af6f3ae7f9      c3             ret
[0x55af6f3ae714]> 
``` 
What a mess! As you can detect at first sight, radare2 identified every single cell of our multidimensional array as an independent variable, in fact the code is mega simple
```
|           0x55af6f3ae72b      c745a0010000.  mov dword [local_60h], 1
|           0x55af6f3ae732      c745a4020000.  mov dword [local_5ch], 2
|           0x55af6f3ae739      c745a8030000.  mov dword [local_58h], 3
|           0x55af6f3ae740      c745ac040000.  mov dword [local_54h], 4
|           0x55af6f3ae747      c745b0050000.  mov dword [local_50h], 5
|           0x55af6f3ae74e      c745b4060000.  mov dword [local_4ch], 6
|           0x55af6f3ae755      c745b8070000.  mov dword [local_48h], 7
|           0x55af6f3ae75c      c745bc080000.  mov dword [local_44h], 8
|           0x55af6f3ae763      c745c0090000.  mov dword [local_40h], 9
|           0x55af6f3ae76a      c745c40a0000.  mov dword [local_3ch], 0xa
|           0x55af6f3ae771      c745c80b0000.  mov dword [local_38h], 0xb ; 11
|           0x55af6f3ae778      c745cc0c0000.  mov dword [local_34h], 0xc ; 12
|           0x55af6f3ae77f      c745d00d0000.  mov dword [local_30h], 0xd ; 13
|           0x55af6f3ae786      c745d40e0000.  mov dword [local_2ch], 0xe ; 14
|           0x55af6f3ae78d      c745d80f0000.  mov dword [local_28h], 0xf ; 15
|           0x55af6f3ae794      c745dc100000.  mov dword [local_24h], 0x10 ; 16
|           0x55af6f3ae79b      c745e0110000.  mov dword [local_20h], 0x11 ; 17
|           0x55af6f3ae7a2      c745e4120000.  mov dword [local_1ch], 0x12 ; 18
|           0x55af6f3ae7a9      c745e8130000.  mov dword [local_18h], 0x13 ; 19
|           0x55af6f3ae7b0      c745ec140000.  mov dword [local_14h], 0x14 ; 2
```
The values are set and then, the needed variables are passed to printf, that's all. You may encounter scenarios like this one sometimes. When we see something like this, we may want to get rid of some useles local_whatever tags, we know that we can delete any disturbin var with avf- and make them look nicer with avfn
```
[0x55af6f3ae714]> afv- local_54h
[0x55af6f3ae714]> afv- local_58h
[0x55af6f3ae714]> afv- local_5ch
[0x55af6f3ae714]> afvn local_60h multiarray
[0x55af6f3ae714]> pdf
/ (fcn) sym.func 230
|   sym.func ();
|           ; var int multiarray @ rbp-0x60
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x55af6f3ae703 (sym.main)
|           0x55af6f3ae714      55             push rbp
|           0x55af6f3ae715      4889e5         mov rbp, rsp
|           0x55af6f3ae718      4883ec60       sub rsp, 0x60           ; '`'
|           0x55af6f3ae71c      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x55af6f3ae725      488945f8       mov qword [local_8h], rax
|           0x55af6f3ae729      31c0           xor eax, eax
|           0x55af6f3ae72b      c745a0010000.  mov dword [multiarray], 1
|           0x55af6f3ae732      c745a4020000.  mov dword [rbp - 0x5c], 2
|           0x55af6f3ae739      c745a8030000.  mov dword [rbp - 0x58], 3
|           0x55af6f3ae740      c745ac040000.  mov dword [rbp - 0x54], 4
```
When dealing with an array, in general terms we just need to note its base address, as if we know the base addr and the size we can get to anything, so label correctly that address and take your notes. But how to inspect those arrays in a more efficient way? The "pf" command in radare2 can help us when it comes to inspecting memory:
```
[0x555e65e677b7]> afvd
var local_8h = 0x7ffdd66dcfb8  0x7a48b8b948f3ac00   ...H..Hz
var multiarray = 0x7ffdd66dcf60  0x0000000200000001   ........ @rsp
[0x555e65e677b7]> pf 20d val  @ 0x7ffdd66dcf60
0x7ffdd66dcf60 [0] {
   val : 0x7ffdd66dcf60 = 1
}
0x7ffdd66dcf64 [1] {
   val : 0x7ffdd66dcf64 = 2
}
0x7ffdd66dcf68 [2] {
   val : 0x7ffdd66dcf68 = 3
}
0x7ffdd66dcf6c [3] {
   val : 0x7ffdd66dcf6c = 4
}
0x7ffdd66dcf70 [4] {
   val : 0x7ffdd66dcf70 = 5
}
0x7ffdd66dcf74 [5] {
   val : 0x7ffdd66dcf74 = 6
}
0x7ffdd66dcf78 [6] {
   val : 0x7ffdd66dcf78 = 7
}
0x7ffdd66dcf7c [7] {
   val : 0x7ffdd66dcf7c = 8
}
0x7ffdd66dcf80 [8] {
   val : 0x7ffdd66dcf80 = 9
}
0x7ffdd66dcf84 [9] {
   val : 0x7ffdd66dcf84 = 10
}
0x7ffdd66dcf88 [10] {
   val : 0x7ffdd66dcf88 = 11
}
0x7ffdd66dcf8c [11] {
   val : 0x7ffdd66dcf8c = 12
}
0x7ffdd66dcf90 [12] {
   val : 0x7ffdd66dcf90 = 13
}
0x7ffdd66dcf94 [13] {
   val : 0x7ffdd66dcf94 = 14
}
0x7ffdd66dcf98 [14] {
   val : 0x7ffdd66dcf98 = 15
}
0x7ffdd66dcf9c [15] {
   val : 0x7ffdd66dcf9c = 16
}
0x7ffdd66dcfa0 [16] {
   val : 0x7ffdd66dcfa0 = 17
}
0x7ffdd66dcfa4 [17] {
   val : 0x7ffdd66dcfa4 = 18
}
0x7ffdd66dcfa8 [18] {
   val : 0x7ffdd66dcfa8 = 19
}
0x7ffdd66dcfac [19] {
   val : 0x7ffdd66dcfac = 20
}
[0x555e65e677b7]> 
```
That was nice! We were able to retrieve 20 signed decimal integers starting from 0x7ffdd66dcf60. After pf we use 20d to indicate that we want to retrieve 20 values using the format string %d starting from that address, we can use other format strings such as %c for chars %f for float or %s, %x for hex or for string. We can even chain format strings doing something like 20iiis to specify that we want to represent three integers and a string, we'll review that more deeply further in this "course".

So briefly, on this perspective having an array of arrays is, on a practical level, almost the same as having a single large array as everything will be together, it is more like a semantic trick for making it easier for us, the h u m a n s, to work with data structures while programming.


But most of the time, specially if we are deing with projects that are somehow more "serious", we can expect to encounter more advanced data structures that may be asociated with objects. At the end, those structures will be comprised sets of arrays, tags of memory addresses and simple variables. That is one of the reasons why I love to work at the low level, everything becomes super simple.

In languages such as C, we can define more complex custom data structures by using struct. Sometimes we may want to have a unique reference for a set of data that is related to a particular topic on your program, for example you may want to store the coordinates of a single geo point, or perhaps store the data of a subject with its name and the final marks of the students or whatever you need to do, you get the concept. Struct is used in C for that, as you can see on the following code:
```c
#include <stdio.h>
#include <stdlib.h>

struct students {
   int a[20];
   char  b[20];
};
 
int main( ) {
        time_t t;
        int i, n;
        srand((unsigned) time(&t));
        struct students s1;

        for( i = 0 ; i < 20 ; i++ ) {
              s1.a[i] = rand() % 11;
        }

        for( i = 0 ; i < 20 ; i++ ) {
              printf("%d ",s1.a[i]);
        }

        return 0;
}
```
As you can see the students structure is defined comprised of an int array and a char array as well, then it is initialized further in the code, also note that this time we use another library, stdlib and rand comes into play. 

Let's check that out:

```
[0x7efc2890e090]> ii
[Imports]
   1 0x55d00da94000    WEAK  NOTYPE _ITM_deregisterTMCloneTable
   2 0x55d00da94610  GLOBAL    FUNC __stack_chk_fail
   3 0x55d00da94620  GLOBAL    FUNC printf
   4 0x55d00da94000  GLOBAL    FUNC __libc_start_main
   5 0x55d00da94630  GLOBAL    FUNC srand
   6 0x55d00da94000    WEAK  NOTYPE __gmon_start__
   7 0x55d00da94640  GLOBAL    FUNC time
   8 0x55d00da94000    WEAK  NOTYPE _ITM_registerTMCloneTable
   9 0x55d00da94000    WEAK    FUNC __cxa_finalize
  10 0x55d00da94650  GLOBAL    FUNC rand
   1 0x55d00da94000    WEAK  NOTYPE _ITM_deregisterTMCloneTable
   4 0x55d00da94000  GLOBAL    FUNC __libc_start_main
   6 0x55d00da94000    WEAK  NOTYPE __gmon_start__
   8 0x55d00da94000    WEAK  NOTYPE _ITM_registerTMCloneTable
   9 0x55d00da94000    WEAK    FUNC __cxa_finalize
```
At first sight, by examining those imports we already know that this program deals with random numbers. This time the block of code we want to analyse is at the main function:
```c
[0x55d00da9477a]> pdf
            ;-- main:
/ (fcn) main 189
|   main ();
|           ; var int local_7ch @ rbp-0x7c
|           ; var int local_78h @ rbp-0x78
|           ; var int local_8h @ rbp-0x8
|              ; DATA XREF from 0x55d00da9468d (entry0)
|           0x55d00da9477a      55             push rbp
|           0x55d00da9477b      4889e5         mov rbp, rsp
|           0x55d00da9477e      4883c480       add rsp, -0x80
|           0x55d00da94782      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x55d00da9478b      488945f8       mov qword [local_8h], rax
|           0x55d00da9478f      31c0           xor eax, eax
|           0x55d00da94791      488d4588       lea rax, qword [local_78h]
|           0x55d00da94795      4889c7         mov rdi, rax
|           0x55d00da94798      b800000000     mov eax, 0
|           0x55d00da9479d      e89efeffff     call sym.imp.time       ; time_t time(time_t *timer)
|           0x55d00da947a2      89c7           mov edi, eax
|           0x55d00da947a4      e887feffff     call sym.imp.srand      ; void srand(int seed)
|           0x55d00da947a9      c74584000000.  mov dword [local_7ch], 0
|       ,=< 0x55d00da947b0      eb35           jmp 0x55d00da947e7
|      .--> 0x55d00da947b2      e899feffff     call sym.imp.rand       ; int rand(void)
|      :|   0x55d00da947b7      89c1           mov ecx, eax
|      :|   0x55d00da947b9      bae9a28b2e     mov edx, 0x2e8ba2e9
|      :|   0x55d00da947be      89c8           mov eax, ecx
|      :|   0x55d00da947c0      f7ea           imul edx
|      :|   0x55d00da947c2      d1fa           sar edx, 1
|      :|   0x55d00da947c4      89c8           mov eax, ecx
|      :|   0x55d00da947c6      c1f81f         sar eax, 0x1f
|      :|   0x55d00da947c9      29c2           sub edx, eax
|      :|   0x55d00da947cb      89d0           mov eax, edx
|      :|   0x55d00da947cd      c1e002         shl eax, 2
|      :|   0x55d00da947d0      01d0           add eax, edx
|      :|   0x55d00da947d2      01c0           add eax, eax
|      :|   0x55d00da947d4      01d0           add eax, edx
|      :|   0x55d00da947d6      29c1           sub ecx, eax
|      :|   0x55d00da947d8      89ca           mov edx, ecx
|      :|   0x55d00da947da      8b4584         mov eax, dword [local_7ch]
|      :|   0x55d00da947dd      4898           cdqe
|      :|   0x55d00da947df      89548590       mov dword [rbp + rax*4 - 0x70], edx
|      :|   0x55d00da947e3      83458401       add dword [local_7ch], 1
|      :|      ; JMP XREF from 0x55d00da947b0 (main)
|      :`-> 0x55d00da947e7      837d8413       cmp dword [local_7ch], 0x13 ; [0x13:4]=-1 ; 19
|      `==< 0x55d00da947eb      7ec5           jle 0x55d00da947b2
|           0x55d00da947ed      c74584000000.  mov dword [local_7ch], 0
|       ,=< 0x55d00da947f4      eb20           jmp 0x55d00da94816
|      .--> 0x55d00da947f6      8b4584         mov eax, dword [local_7ch]
|      :|   0x55d00da947f9      4898           cdqe
|      :|   0x55d00da947fb      8b448590       mov eax, dword [rbp + rax*4 - 0x70]
|      :|   0x55d00da947ff      89c6           mov esi, eax
|      :|   0x55d00da94801      488d3dbc0000.  lea rdi, qword [0x55d00da948c4] ; "%d "
|      :|   0x55d00da94808      b800000000     mov eax, 0
|      :|   0x55d00da9480d      e80efeffff     call sym.imp.printf     ; int printf(const char *format)
|      :|   0x55d00da94812      83458401       add dword [local_7ch], 1
|      :|      ; JMP XREF from 0x55d00da947f4 (main)
|      :`-> 0x55d00da94816      837d8413       cmp dword [local_7ch], 0x13 ; [0x13:4]=-1 ; 19
|      `==< 0x55d00da9481a      7eda           jle 0x55d00da947f6
|           0x55d00da9481c      b800000000     mov eax, 0
|           0x55d00da94821      488b75f8       mov rsi, qword [local_8h]
|           0x55d00da94825      644833342528.  xor rsi, qword fs:[0x28]
|       ,=< 0x55d00da9482e      7405           je 0x55d00da94835
|       |   0x55d00da94830      e8dbfdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x55d00da94835      c9             leave
\           0x55d00da94836      c3             ret
[0x55d00da9477a]> 
```
The block here may seem bigger that the previous ones but don't let that scare you. On first sight we can detect a couple of loops, the first one probably initializes the array and the second one for sure prints its values one after another as we can see printf being called.

By the way we can even mark that on the disasm, so we can better inspect the whole thing. With CCu comment @ addr we can add a comment to be shown next to a particular mem address.

```
[0x55d00da9477a]> CCu "print array" @ 0x55d00da947f4


|           0x55d00da947ed      c74584000000.  mov dword [local_7ch], 0
|       ,=< 0x55d00da947f4      eb20           jmp 0x55d00da94816      ; "print array"
|      .--> 0x55d00da947f6      8b4584         mov eax, dword [local_7ch]
|      :|   0x55d00da947f9      4898           cdqe
|      :|   0x55d00da947fb      8b448590       mov eax, dword [rbp + rax*4 - 0x70]
|      :|   0x55d00da947ff      89c6           mov esi, eax
|      :|   0x55d00da94801      488d3dbc0000.  lea rdi, qword [0x55d00da948c4] ; "%d "
```
We can also list all of the comments easily with
```
[0x55d00da9477a]> CC
0x00000000 CCu "[28] ----- section size 254 named .shstrtab"
0x55d00da94000 CCu "[38] m-rw- section size 64 named ehdr"
0x55d00da94040 CCu "[29] m-r-- section size 504 named PHDR"
0x55d00da94238 CCu "[30] m-r-- section size 28 named INTERP"
0x55d00da94254 CCu "[34] m-r-- section size 68 named NOTE"
0x55d00da94274 CCu "[03] --r-- section size 36 named .note.gnu.build_id"
0x55d00da94298 CCu "[04] --r-- section size 28 named .gnu.hash"
0x55d00da942b8 CCu "[05] --r-- section size 264 named .dynsym"
0x55d00da943c0 CCu "[06] --r-- section size 170 named .dynstr"
0x55d00da9446a CCu "[07] --r-- section size 22 named .gnu.version"
0x55d00da94480 CCu "[08] --r-- section size 48 named .gnu.version_r"
0x55d00da944b0 CCu "[09] --r-- section size 192 named .rela.dyn"
0x55d00da94570 CCu "[10] --r-- section size 120 named .rela.plt"
0x55d00da945e8 CCu "[11] --r-x section size 23 named .init"
0x55d00da94600 CCu "[12] --r-x section size 96 named .plt"
0x55d00da94660 CCu "[13] --r-x section size 8 named .plt.got"
0x55d00da94670 CCu "[14] --r-x section size 578 named .text"
0x55d00da947f4 CCu "\"print array\""
0x55d00da948b4 CCu "[15] --r-x section size 9 named .fini"
0x55d00da948c0 CCu "[16] --r-- section size 8 named .rodata"
0x55d00da948c8 CCu "[35] m-r-- section size 60 named GNU_EH_FRAME"
0x55d00da94908 CCu "[18] --r-- section size 264 named .eh_frame"
0x55d00dc94d98 CCu "[37] m-r-- section size 616 named GNU_RELRO"
0x55d00dc94da0 CCu "[20] --rw- section size 8 named .fini_array"
0x55d00dc94da8 CCu "[33] m-rw- section size 496 named DYNAMIC"
0x55d00dc94f98 CCu "[22] --rw- section size 104 named .got"
0x55d00dc95000 CCu "[23] --rw- section size 16 named .data"
0x55d00dc95010 CCu "[24] --rw- section size 0 named .bss"
```
Let's now get to the first loop:
```
[0x55d00da9477a]> pdf
            ;-- main:
/ (fcn) main 189
|   main ();
|           ; var int local_7ch @ rbp-0x7c
|           ; var int local_78h @ rbp-0x78
|           ; var int local_8h @ rbp-0x8
|              ; DATA XREF from 0x55d00da9468d (entry0)
```
This time the program sets three variables, the stack guard and a couple of vars, local_7ch used for storing i (the loop counter) and then we have local_78h that seems to be related to the tim call.

Let's look closer on that:
```
|           0x55d00da94791      488d4588       lea rax, qword [local_78h]
|           0x55d00da94795      4889c7         mov rdi, rax
|           0x55d00da94798      b800000000     mov eax, 0
|           0x55d00da9479d      e89efeffff     call sym.imp.time       ; time_t time(time_t *timer)
|           0x55d00da947a2      89c7           mov edi, eax
|           0x55d00da947a4      e887feffff     call sym.imp.srand      ; void srand(int seed)
|           0x55d00da947a9      c74584000000.  mov dword [local_7ch], 0
```
As you can see, the memory address of local_78h is passed to time() as a parameter. Then the result of the call (stored in eax) is again pased to srand as the seed, after that the first loop counter is initialized (i=0). The time function works like this: time_t time( time_t *second ) the time function accepts single parameter: second. This parameter is used to set the time_t object which store the time (http://www.cplusplus.com/reference/ctime/time_t/) And returns current calender time as a object of type time_t. The srand function stands for seed rand (?) I guess and it is used for setting the seed of the random number generrator to be used by the rand() function. The random number generator used by rand() needs a seed as you can imagine it computes a random number by using a mathematical formula (and thus it needs an input). It is important to mark that, using the same seed will procude the same later on on the code. 

Related to the code, as you can see, the output of time function is passed to srand, time is used as the random seed a lot of times cause is one of the most random values we can have inside our machine, other stuff like the mouse position or a random set of words is used as well, more complex systems such as the ones used in banking can even make use of temperature/preassure sensors and so on.

So now that srand has been set, the program will be able to generate nice random numbers by calling the rand function.

With our rand function ready, we'll dive into the first loop:
```
|           0x55d00da947a2      89c7           mov edi, eax
|           0x55d00da947a4      e887feffff     call sym.imp.srand      ; void srand(int seed)
|           0x55d00da947a9      c74584000000.  mov dword [local_7ch], 0
|       ,=< 0x55d00da947b0      eb35           jmp 0x55d00da947e7
|      .--> 0x55d00da947b2      e899feffff     call sym.imp.rand       ; int rand(void)
|      :|   0x55d00da947b7      89c1           mov ecx, eax
|      :|   0x55d00da947b9      bae9a28b2e     mov edx, 0x2e8ba2e9
|      :|   0x55d00da947be      89c8           mov eax, ecx
|      :|   0x55d00da947c0      f7ea           imul edx
|      :|   0x55d00da947c2      d1fa           sar edx, 1
|      :|   0x55d00da947c4      89c8           mov eax, ecx
|      :|   0x55d00da947c6      c1f81f         sar eax, 0x1f
|      :|   0x55d00da947c9      29c2           sub edx, eax
|      :|   0x55d00da947cb      89d0           mov eax, edx
|      :|   0x55d00da947cd      c1e002         shl eax, 2
|      :|   0x55d00da947d0      01d0           add eax, edx
|      :|   0x55d00da947d2      01c0           add eax, eax
|      :|   0x55d00da947d4      01d0           add eax, edx
|      :|   0x55d00da947d6      29c1           sub ecx, eax
|      :|   0x55d00da947d8      89ca           mov edx, ecx
|      :|   0x55d00da947da      8b4584         mov eax, dword [local_7ch]
|      :|   0x55d00da947dd      4898           cdqe
|      :|   0x55d00da947df      89548590       mov dword [rbp + rax*4 - 0x70], edx
|      :|   0x55d00da947e3      83458401       add dword [local_7ch], 1
```
For analysing this block, the most fundamental part is to have the following: s1.a[i] = rand() % 11; very present. We can break it in three parts (as you should already know), first we generate the random number, then we do the % 11, then we store the result inside s1.a[i].

So the first part is very clear:
```
|      .--> 0x55d00da947b2      e899feffff     call sym.imp.rand       ; int rand(void)
|      :|   0x55d00da947b7      89c1           mov ecx, eax
```
With rand we obtain a random number (eax) then we store it in ecx as we will operate with it.
The next part should be the % 10, let's see;
```
|      :|   0x55d00da947b9      bae9a28b2e     mov edx, 0x2e8ba2e9
|      :|   0x55d00da947be      89c8           mov eax, ecx
|      :|   0x55d00da947c0      f7ea           imul edx
|      :|   0x55d00da947c2      d1fa           sar edx, 1
|      :|   0x55d00da947c4      89c8           mov eax, ecx
|      :|   0x55d00da947c6      c1f81f         sar eax, 0x1f
|      :|   0x55d00da947c9      29c2           sub edx, eax
|      :|   0x55d00da947cb      89d0           mov eax, edx
|      :|   0x55d00da947cd      c1e002         shl eax, 2
|      :|   0x55d00da947d0      01d0           add eax, edx
|      :|   0x55d00da947d2      01c0           add eax, eax
|      :|   0x55d00da947d4      01d0           add eax, edx
|      :|   0x55d00da947d6      29c1           sub ecx, eax|      :|   0x55d00da947b9      bae9a28b2e     mov edx, 0x2e8ba2e9
|      :|   0x55d00da947be      89c8           mov eax, ecx
|      :|   0x55d00da947c0      f7ea           imul edx
|      :|   0x55d00da947c2      d1fa           sar edx, 1
|      :|   0x55d00da947c4      89c8           mov eax, ecx
|      :|   0x55d00da947c6      c1f81f         sar eax, 0x1f
|      :|   0x55d00da947c9      29c2           sub edx, eax
|      :|   0x55d00da947cb      89d0           mov eax, edx
|      :|   0x55d00da947cd      c1e002         shl eax, 2
|      :|   0x55d00da947d0      01d0           add eax, edx
|      :|   0x55d00da947d2      01c0           add eax, eax
|      :|   0x55d00da947d4      01d0           add eax, edx
|      :|   0x55d00da947d6      29c1           sub ecx, eax
```
When dealing with "complex" situations "we don't understand" like this one, we have at least a couple of options. The first option is to get a general grasp on whats going on, on the block of code and proceed looking at the big picture, we can try to set a couple of breakpoints before and after we get into the code block, see how a value gets in and look at the output.

On the other hand, we can inspect the function step by step, tracing the input, setting breakpoints wherever a value is changed. Be careful if you chose this one, cause some functions (ex: win api calls, syscalls, big projects, whatever) can be huge and you'll probably lose a lot of time.
```
|      :|   0x55d00da947be b    89c8           mov eax, ecx
|      :|   0x55d00da947c0      f7ea           imul edx
|      :|   0x55d00da947c2 b    d1fa           sar edx, 1
|      :|   0x55d00da947c4 b    89c8           mov eax, ecx
|      :|   0x55d00da947c6      c1f81f         sar eax, 0x1f
|      :|   0x55d00da947c9 b    29c2           sub edx, eax
|      :|   0x55d00da947cb      89d0           mov eax, edx
|      :|   0x55d00da947cd      c1e002         shl eax, 2
|      :|   0x55d00da947d0 b    01d0           add eax, edx
|      :|   0x55d00da947d2 b    01c0           add eax, eax
|      :|   0x55d00da947d4 b    01d0           add eax, edx
|      :|   0x55d00da947d6      29c1           sub ecx, eax
|      :|   0x55d00da947d8      89ca           mov edx, ecx
``` 

```
|      .--> 0x555600e8b7b2      e899feffff     call sym.imp.rand       ; int rand(void)
|      :|   0x555600e8b7b7      89c1           mov ecx, eax
|      :|   0x555600e8b7b9      bae9a28b2e     mov edx, 0x2e8ba2e9     ; rdx

[0x555600e8b7be]> dr eax
0x591fb69a
[0x555600e8b7be]> dr edx
0x2e8ba2e9

|      :|   0x555600e8b7be b    89c8           mov eax, ecx
|      :|   0x555600e8b7c0      f7ea           imul edx
[0x555600e8b7be]> dr edx
0x10344fbf

|      :|   0x555600e8b7c4      89c8           mov eax, ecx
|      :|   0x555600e8b7c6      c1f81f         sar eax, 0x1f
|      :|   ;-- rip:
[0x555600e8b7be]> dr eax
0x00000000
[0x555600e8b7be]> dr edx
0x081a27df

|      :|   0x555600e8b7c9 b    29c2           sub edx, eax
|      :|   0x555600e8b7cb      89d0           mov eax, edx
|      :|   0x555600e8b7cd      c1e002         shl eax, 2

[0x555600e8b7be]> dr eax
0x20689f7c
[0x555600e8b7be]> dr edx
0x081a27df
[0x555600e8b7be]> 

[...]

[0x555600e8b7be]> dr
rax = 0x591fb695
rbx = 0x00000000
rcx = 0x00000005


```
The final result is 0x5 -> dec 5, so the random number that has been generated % 10 is 5. Note that the rand() function returns a number that goes from 0x0 to 0xFFFFFFFFFFFFFFFF (18446744073709551615) on a x64 machine, then the modulus is used for "cutting" that and setting a max of 50. As you can see on this case rand returned: 0x591fb69a (1495250586) then some operations such as shift aligns and multiplications happen to cut that to what is relative to 10.

If you wish to go deeper on that topic I suggest you reading the discusion here: https://stackoverflow.com/questions/8021772/assembly-language-how-to-do-modulo 

Also note that the mod operation can be done in many ways! There are ways that would look very much clearer than the one used here but the compiler won't think about how nice the thing will look, the compiler will try to maximize the performance and sometimes using a particular set of instrructions can result in a quicker execution on that context.

So, then after that, we see the value being stored in the array the same way we seen before:

```
|      :|   0x555600e8b7da      8b4584         mov eax, dword [local_7ch]
|      :|   0x555600e8b7dd      4898           cdqe
|      :|   0x555600e8b7df      89548590       mov dword [rbp + rax*4 - 0x70], edx
|      :|   0x555600e8b7e3      83458401       add dword [local_7ch], 1
|      :|      ; JMP XREF from 0x555600e8b7b0 (main)
|      :`-> 0x555600e8b7e7      837d8413       cmp dword [local_7ch], 0x13 ; [0x13:4]=-1 ; 19
|      `==< 0x555600e8b7eb      7ec5           jle 0x555600e8b7b2
```


And the loop goes on 20 times. At this point, when dealing with complex data structures that hold or may hold relevant information, it turns out very useful to keep them on track. We may have a general idea on how are they structured or we may have some extra info like a .h file or something. In radare2 it is posible to "map" a definition for the structure to a particular memory address using td and tl. 

As we already know about the code, let's set that struct in radare2 and map it:
```
"td struct students {int a[20]; char  b[20];}"
tl students = 0x7FFD69D8C94C
```
So we can map that struct to the address we see by inspecting the address that we think it may correspond to the starting value of, for example, the array that is being initialized, and then hit dc and see how the program updates (sets) those array values:
```
[0x555600e8b7be]> dc
hit breakpoint at: 555600e8b7be
[0x555600e8b7be]> tl
(students)
 a : 0x7ffd69d8c94c = [ 0, 5, 8, 5, 3, 1, 6, 9, 2, 5, 8, 9, 2, 4, 7, 10, 3, 6, 6, 0 ]
 b : 0x7ffd69d8c99c = 

```
Having that said, it is important to remark that we can actually we wrong in many ways (like in life), we can miss the base addr and figure out the wrong struct, we gotta use the struct that best fits to our analysis.

Let us now finish this one with a last example:
```c
#include <stdio.h>
#include <string.h>
 
struct Books {
   char  title[50];
   char  author[50];
   char  subject[100];
   int   book_id;
};
 
int main( ) {

   struct Books Book1;        /* Declare Book1 of type Book */
   struct Books Book2;        /* Declare Book2 of type Book */
 
   /* book 1 specification */
   strcpy( Book1.title, "C Programming");
   strcpy( Book1.author, "Nuha Ali"); 
   strcpy( Book1.subject, "C Programming Tutorial");
   Book1.book_id = 6495407;

   /* book 2 specification */
   strcpy( Book2.title, "Telecom Billing");
   strcpy( Book2.author, "Zara Ali");
   strcpy( Book2.subject, "Telecom Billing Tutorial");
   Book2.book_id = 6495700;
 
   /* print Book1 info */
   printf( "Book 1 title : %s\n", Book1.title);
   printf( "Book 1 author : %s\n", Book1.author);
   printf( "Book 1 subject : %s\n", Book1.subject);
   printf( "Book 1 book_id : %d\n", Book1.book_id);

   /* print Book2 info */
   printf( "Book 2 title : %s\n", Book2.title);
   printf( "Book 2 author : %s\n", Book2.author);
   printf( "Book 2 subject : %s\n", Book2.subject);
   printf( "Book 2 book_id : %d\n", Book2.book_id);

   return 0;
}
```
And the disasm looks like:

```
[0x56315b93e6aa]> pdf
            ;-- main:
/ (fcn) sym.main 529
|   sym.main ();
|           ; var int local_1b0h @ rbp-0x1b0
|           ; var int local_e8h @ rbp-0xe8
|           ; var int local_e0h @ rbp-0xe0
|           ; var int local_18h @ rbp-0x18
|           ; var int local_8h @ rbp-0x8
|              ; DATA XREF from 0x56315b93e5bd (entry0)
|           0x56315b93e6aa      55             push rbp
|           0x56315b93e6ab      4889e5         mov rbp, rsp
|           0x56315b93e6ae      4881ecb00100.  sub rsp, 0x1b0
|           0x56315b93e6b5      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x56315b93e6be      488945f8       mov qword [local_8h], rax
|           0x56315b93e6c2      31c0           xor eax, eax
|           0x56315b93e6c4      488d8550feff.  lea rax, qword [local_1b0h]
|           0x56315b93e6cb      48ba43205072.  movabs rdx, 0x6172676f72502043
|           0x56315b93e6d5      488910         mov qword [rax], rdx
|           0x56315b93e6d8      c740086d6d69.  mov dword [rax + 8], 0x6e696d6d ; [0x6e696d6d:4]=-1
|           0x56315b93e6df      66c7400c6700   mov word [rax + 0xc], 0x67 ; 'g' ; [0x67:2]=0xffff ; 103
|           0x56315b93e6e5      488d8550feff.  lea rax, qword [local_1b0h]
|           0x56315b93e6ec      4883c032       add rax, 0x32           ; '2'
|           0x56315b93e6f0      48b94e756861.  movabs rcx, 0x696c41206168754e
|           0x56315b93e6fa      488908         mov qword [rax], rcx
|           0x56315b93e6fd      c6400800       mov byte [rax + 8], 0
|           0x56315b93e701      488d8550feff.  lea rax, qword [local_1b0h]
|           0x56315b93e708      4883c064       add rax, 0x64           ; 'd'
|           0x56315b93e70c      48ba43205072.  movabs rdx, 0x6172676f72502043
|           0x56315b93e716      48b96d6d696e.  movabs rcx, 0x755420676e696d6d
|           0x56315b93e720      488910         mov qword [rax], rdx
|           0x56315b93e723      48894808       mov qword [rax + 8], rcx
|           0x56315b93e727      c74010746f72.  mov dword [rax + 0x10], 0x69726f74 ; [0x69726f74:4]=-1
|           0x56315b93e72e      66c74014616c   mov word [rax + 0x14], 0x6c61 ; [0x6c61:2]=0xffff
|           0x56315b93e734      c6401600       mov byte [rax + 0x16], 0
|           0x56315b93e738      c78518ffffff.  mov dword [local_e8h], 0x631caf
|           0x56315b93e742      488d8520ffff.  lea rax, qword [local_e0h]
|           0x56315b93e749      48ba54656c65.  movabs rdx, 0x206d6f63656c6554
|           0x56315b93e753      48b942696c6c.  movabs rcx, 0x676e696c6c6942
|           0x56315b93e75d      488910         mov qword [rax], rdx
|           0x56315b93e760      48894808       mov qword [rax + 8], rcx
|           0x56315b93e764      488d8520ffff.  lea rax, qword [local_e0h]
|           0x56315b93e76b      4883c032       add rax, 0x32           ; '2'
|           0x56315b93e76f      48ba5a617261.  movabs rdx, 0x696c41206172615a
|           0x56315b93e779      488910         mov qword [rax], rdx
|           0x56315b93e77c      c6400800       mov byte [rax + 8], 0
|           0x56315b93e780      488d8520ffff.  lea rax, qword [local_e0h]
|           0x56315b93e787      4883c064       add rax, 0x64           ; 'd'
|           0x56315b93e78b      48ba54656c65.  movabs rdx, 0x206d6f63656c6554
|           0x56315b93e795      48b942696c6c.  movabs rcx, 0x20676e696c6c6942
|           0x56315b93e79f      488910         mov qword [rax], rdx
|           0x56315b93e7a2      48894808       mov qword [rax + 8], rcx
|           0x56315b93e7a6      48b95475746f.  movabs rcx, 0x6c6169726f747554
|           0x56315b93e7b0      48894810       mov qword [rax + 0x10], rcx
|           0x56315b93e7b4      c6401800       mov byte [rax + 0x18], 0
|           0x56315b93e7b8      c745e8d41d63.  mov dword [local_18h], 0x631dd4
|           0x56315b93e7bf      488d8550feff.  lea rax, qword [local_1b0h]
|           0x56315b93e7c6      4889c6         mov rsi, rax
|           0x56315b93e7c9      488d3d740100.  lea rdi, qword str.Book_1_title_:__s ; 0x56315b93e944 ; "Book 1 title : %s\n"
|           0x56315b93e7d0      b800000000     mov eax, 0
|           0x56315b93e7d5      e8a6fdffff     call sym.imp.printf     ; int printf(const char *format)
|           0x56315b93e7da      488d8550feff.  lea rax, qword [local_1b0h]
|           0x56315b93e7e1      4883c032       add rax, 0x32           ; '2'
|           0x56315b93e7e5      4889c6         mov rsi, rax
|           0x56315b93e7e8      488d3d680100.  lea rdi, qword str.Book_1_author_:__s ; 0x56315b93e957 ; "Book 1 author : %s\n"
|           0x56315b93e7ef      b800000000     mov eax, 0
|           0x56315b93e7f4      e887fdffff     call sym.imp.printf     ; int printf(const char *format)
|           0x56315b93e7f9      488d8550feff.  lea rax, qword [local_1b0h]
|           0x56315b93e800      4883c064       add rax, 0x64           ; 'd'
|           0x56315b93e804      4889c6         mov rsi, rax
|           0x56315b93e807      488d3d5d0100.  lea rdi, qword str.Book_1_subject_:__s ; 0x56315b93e96b ; "Book 1 subject : %s\n"
|           0x56315b93e80e      b800000000     mov eax, 0
|           0x56315b93e813      e868fdffff     call sym.imp.printf     ; int printf(const char *format)
|           0x56315b93e818      8b8518ffffff   mov eax, dword [local_e8h]
|           0x56315b93e81e      89c6           mov esi, eax
|           0x56315b93e820      488d3d590100.  lea rdi, qword str.Book_1_book_id_:__d ; 0x56315b93e980 ; "Book 1 book_id : %d\n"
|           0x56315b93e827      b800000000     mov eax, 0
|           0x56315b93e82c      e84ffdffff     call sym.imp.printf     ; int printf(const char *format)
|           0x56315b93e831      488d8520ffff.  lea rax, qword [local_e0h]
|           0x56315b93e838      4889c6         mov rsi, rax
|           0x56315b93e83b      488d3d530100.  lea rdi, qword str.Book_2_title_:__s ; 0x56315b93e995 ; "Book 2 title : %s\n"
|           0x56315b93e842      b800000000     mov eax, 0
|           0x56315b93e847      e834fdffff     call sym.imp.printf     ; int printf(const char *format)
|           0x56315b93e84c      488d8520ffff.  lea rax, qword [local_e0h]
|           0x56315b93e853      4883c032       add rax, 0x32           ; '2'
|           0x56315b93e857      4889c6         mov rsi, rax
|           0x56315b93e85a      488d3d470100.  lea rdi, qword str.Book_2_author_:__s ; 0x56315b93e9a8 ; "Book 2 author : %s\n"
|           0x56315b93e861      b800000000     mov eax, 0
|           0x56315b93e866      e815fdffff     call sym.imp.printf     ; int printf(const char *format)
|           0x56315b93e86b      488d8520ffff.  lea rax, qword [local_e0h]
|           0x56315b93e872      4883c064       add rax, 0x64           ; 'd'
|           0x56315b93e876      4889c6         mov rsi, rax
|           0x56315b93e879      488d3d3c0100.  lea rdi, qword str.Book_2_subject_:__s ; 0x56315b93e9bc ; "Book 2 subject : %s\n"
|           0x56315b93e880      b800000000     mov eax, 0
|           0x56315b93e885      e8f6fcffff     call sym.imp.printf     ; int printf(const char *format)
|           0x56315b93e88a      8b45e8         mov eax, dword [local_18h]
|           0x56315b93e88d      89c6           mov esi, eax
|           0x56315b93e88f      488d3d3b0100.  lea rdi, qword str.Book_2_book_id_:__d ; 0x56315b93e9d1 ; "Book 2 book_id : %d\n"
|           0x56315b93e896      b800000000     mov eax, 0
|           0x56315b93e89b      e8e0fcffff     call sym.imp.printf     ; int printf(const char *format)
|           0x56315b93e8a0      b800000000     mov eax, 0
|           0x56315b93e8a5      488b75f8       mov rsi, qword [local_8h]
|           0x56315b93e8a9      644833342528.  xor rsi, qword fs:[0x28]
|       ,=< 0x56315b93e8b2      7405           je 0x56315b93e8b9
|       |   0x56315b93e8b4      e8b7fcffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x56315b93e8b9      c9             leave
\           0x56315b93e8ba      c3             ret
[0x56315b93e6aa]> 
```
Again, don't let that code scare you, as it is so rrepetitive. We can split the code in two main sections, first the code initializes some data and then it prints it out. On that first section, we can also identify some kind of pattern, two blocks, both ending with one assignment:

```
|           0x56315b93e72e      66c74014616c   mov word [rax + 0x14], 0x6c61 ; [0x6c61:2]=0xffff
|           0x56315b93e734      c6401600       mov byte [rax + 0x16], 0
|           0x56315b93e738      c78518ffffff.  mov dword [local_e8h], 0x631caf

|           0x56315b93e7b0      48894810       mov qword [rax + 0x10], rcx
|           0x56315b93e7b4      c6401800       mov byte [rax + 0x18], 0
|           0x56315b93e7b8      c745e8d41d63.  mov dword [local_18h], 0x631dd4
```
So let's analyse one of them and so we can figure the whole thing out. Reading from top to down we see:
```
|           0x56315b93e6cb      48ba43205072.  movabs rdx, 0x6172676f72502043
|           0x56315b93e6d5      488910         mov qword [rax], rdx
|           0x56315b93e6d8      c740086d6d69.  mov dword [rax + 8], 0x6e696d6d ; [0x6e696d6d:4]=-1
|           0x56315b93e6df      66c7400c6700   mov word [rax + 0xc], 0x67 ; 'g' ; [0x67:2]=0xffff ; 103
|           0x56315b93e6e5      488d8550feff.  lea rax, qword [local_1b0h]
```
As you can see, some big hex chunks are being moved to memory starting at local_1b0h moveabs is used as we intend to move larger chunks. And if we put everything together: 432050726f6772616d6d696e67 = C Programming in ASCII. (remember the endianess). Known that, you can figure out the rest of the code. It is important to remark that even though we use strcpy, the program does it itself, instead of calling whatever function.


```
[0x56315b93e6aa]> "td struct Books { char  title[50]; char  author[50]; char  subject[100]; int book_id;};"
[0x56315b93e6aa]> tl
[0x56315b93e6aa]> td
Invalid use of td. See td? for help
^Cx56315b93e6aa]> 
[0x56315b93e6aa]> 
[0x56315b93e6aa]> db 0x56315b93e6cb
[0x56315b93e6aa]> db 0x56315b93e749
[0x56315b93e6aa]> dc
hit breakpoint at: 56315b93e6cb
[0x56315b93e6aa]> afvd
var local_8h = 0x7fff0a95f358  0x4332774ba5ead400   ....Kw2C
var local_1b0h = 0x7fff0a95f1b0  0x00007fff0a95f370   p....... @rsp stack R W 0x1 -->  rdi
var local_e8h = 0x7fff0a95f278  0x00007fe2f4b21710   ........ (unk0) R W 0x7fff0a9d2000 -->  ([vvar]) map.vdso_._r_x R X 'jg 0x7fff0a9d2047' '[vdso]'
var local_e0h = 0x7fff0a95f280  0x00007fe2f46ba787   ..k..... (__vdso_getcpu)
var local_18h = 0x7fff0a95f348  0x000056315b93e5a0   ...[1V.. (LOAD0) (/home/red/c/chapter6/structs) r12 entry0 program R X 'xor ebp, ebp' 'structs'
[0x56315b93e6aa]> tl Books = 0x7fff0a95f1b0
[0x56315b93e6aa]> tl
(Books)
   title : 0x7fff0a95f1b0 = p.....
  author : 0x7fff0a95f1e2 = ....
 subject : 0x7fff0a95f214 = 
 book_id : 0x7fff0a95f278 = 4105312016
[0x56315b93e6aa]> dc
hit breakpoint at: 56315b93e749
[0x56315b93e749]> tl
(Books)
   title : 0x7fff0a95f1b0 = C Programming
  author : 0x7fff0a95f1e2 = Nuha Ali
 subject : 0x7fff0a95f214 = C Programming Tutorial
 book_id : 0x7fff0a95f278 = 6495407
[0x56315b93e749]> 
```
Also note that we can "link" a struct to multiple data addresses and thus monitor multiple memory segments while the program goes on.


Aaand thats all for this post, during the following posts we'll be go deeper on these topics.