---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 10 (more pointers and dynamic structs)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_10.png
featured_image: assets/images/radare2/radare2_10.png
---
As pointers and dynamic memory in general are a very relevant topics that play a criticcal role in modern programs they deserve more than one post. If you wanna get into vuln research or exploit writting having a perfect understanding of how memory is managed in modern software is a must, if you are up to get into security research or reverse engineering, the ability to interpret what the program is doing (/ what a cpu is doing) at a given time on a given context is fundamental.

So let's start with this following program over here:
```C
#include <stdio.h>
#include <stdlib.h>
 
main() {

int * ipoint;


  ipoint  = (int *) malloc (sizeof(int));
  *ipoint = 3;
  
  
  printf ("%p \n",ipoint);


  printf ("%i\n",*ipoint);  
  
  ipoint ++;
  
  printf ("%p\n",ipoint);
 

  printf ("%i\n",*ipoint); 
  getchar();
}
```
The program starts by allocating memory space, the size of an int in heap, a pointer to that space is declared.  That space is then initialized by 3dec, note that * is used for referencing the space pointed by that pointer if * is not used ipoint = address, then the memory address is printed and then the value. Then the program does ipoint++, what will happen? 3+1? or memory address +1?

You should already know this.... but let's actually see it inside radare2:

On this example we already know what we are looking for but, radare2 has many cool ways to provide you with interesting information, that can get you faster to the point. Let's try agc:
```
[0x55a93cbe56da]> agc
                          ┌────────────────────┐
                          │  main              │
                          └────────────────────┘
                                v
                                │
      ┌─────────────────────────│
      │                         └─────────────────────────┐
      │                         │                         │
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│  sym.imp.malloc    │    │  sym.imp.printf    │    │  sym.imp.getchar   │
└────────────────────┘    └────────────────────┘    └────────────────────┘
```
agc analyses the call graph, so in this case we can quickly identify malloc, printf and getchar being called inside main. This is useful ass we may have interesting "circuits" or "ways" between functions we want to analyse.

Let's proceed with pdf:

```
[0x55a93cbe56da]> pdf
            ; DATA XREF from entry0 @ 0x55a93cbe55ed
┌ 147: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           0x55a93cbe56da      55             push rbp
│           0x55a93cbe56db      4889e5         mov rbp, rsp
│           0x55a93cbe56de      4883ec10       sub rsp, 0x10
│           0x55a93cbe56e2      bf04000000     mov edi, 4
│           0x55a93cbe56e7      e8c4feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x55a93cbe56ec      488945f8       mov qword [var_8h], rax
│           0x55a93cbe56f0      488b45f8       mov rax, qword [var_8h]
│           0x55a93cbe56f4      c70003000000   mov dword [rax], 3
│           0x55a93cbe56fa      488b45f8       mov rax, qword [var_8h]
│           0x55a93cbe56fe      4889c6         mov rsi, rax
│           0x55a93cbe5701      488d3dec0000.  lea rdi, str.p          ; 0x55a93cbe57f4 ; "%p \n"
│           0x55a93cbe5708      b800000000     mov eax, 0
│           0x55a93cbe570d      e87efeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55a93cbe5712      488b45f8       mov rax, qword [var_8h]
│           0x55a93cbe5716      8b00           mov eax, dword [rax]
│           0x55a93cbe5718      89c6           mov esi, eax
│           0x55a93cbe571a      488d3dd80000.  lea rdi, [0x55a93cbe57f9] ; "%i\n"
│           0x55a93cbe5721      b800000000     mov eax, 0
│           0x55a93cbe5726      e865feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55a93cbe572b      488345f804     add qword [var_8h], 4
│           0x55a93cbe5730      488b45f8       mov rax, qword [var_8h]
│           0x55a93cbe5734      4889c6         mov rsi, rax
│           0x55a93cbe5737      488d3dbf0000.  lea rdi, [0x55a93cbe57fd] ; "%p\n"
│           0x55a93cbe573e      b800000000     mov eax, 0
│           0x55a93cbe5743      e848feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55a93cbe5748      488b45f8       mov rax, qword [var_8h]
│           0x55a93cbe574c      8b00           mov eax, dword [rax]
│           0x55a93cbe574e      89c6           mov esi, eax
│           0x55a93cbe5750      488d3da20000.  lea rdi, [0x55a93cbe57f9] ; "%i\n"
│           0x55a93cbe5757      b800000000     mov eax, 0
│           0x55a93cbe575c      e82ffeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55a93cbe5761      e83afeffff     call sym.imp.getchar    ; int getchar(void)
│           0x55a93cbe5766      b800000000     mov eax, 0
│           0x55a93cbe576b      c9             leave
└           0x55a93cbe576c      c3             ret
[0x55a93cbe56da]> 
```
As usual, let's dissect the function in multiple parts, the first one calls malloc
```
│           0x55a93cbe56de      4883ec10       sub rsp, 0x10
│           0x55a93cbe56e2      bf04000000     mov edi, 4
│           0x55a93cbe56e7      e8c4feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x55a93cbe56ec      488945f8       mov qword [var_8h], rax
```
And as we see, the program keeps some space on stack for static variables, and reserves 4 bytes using malloc, stores the resulting addres (pointer) to var_8h
```
│           0x55a93cbe56fe      4889c6         mov rsi, rax
│           0x55a93cbe5701      488d3dec0000.  lea rdi, str.p          ; 0x55a93cbe57f4 ; "%p \n"
│           0x55a93cbe5708      b800000000     mov eax, 0
│           0x55a93cbe570d      e87efeffff     call sym.imp.printf     ; int printf(const char *format)
```
Then, the contents of rax will get printed, as rax holds the pointer returned by malloc, what will ger printed is a pointer:
```
│           0x55a93cbe5712      488b45f8       mov rax, qword [var_8h]
│           0x55a93cbe5716      8b00           mov eax, dword [rax]
│           0x55a93cbe5718      89c6           mov esi, eax
│           0x55a93cbe571a      488d3dd80000.  lea rdi, [0x55a93cbe57f9] ; "%i\n"
│           0x55a93cbe5721      b800000000     mov eax, 0
│           0x55a93cbe5726      e865feffff     call sym.imp.printf     ; int printf(const char *format)
```
Then a printf is called again, but this time, look at the second line, the CONTENT is passed, instead of an address, let's see what happens now:
```
│           0x55a93cbe572b      488345f804     add qword [var_8h], 4
│           0x55a93cbe5730      488b45f8       mov rax, qword [var_8h]
│           0x55a93cbe5734      4889c6         mov rsi, rax
│           0x55a93cbe5737      488d3dbf0000.  lea rdi, [0x55a93cbe57fd] ; "%p\n"
│           0x55a93cbe573e      b800000000     mov eax, 0
│           0x55a93cbe5743      e848feffff     call sym.imp.printf     ; int printf(const char *format)
```
We add 4 to the content of var_8h, as the content of var_8h is a pointer 3 won't turno into 4 or 7 or whatever. Note that as we do pointer++ and we are dealing with an INT pointer, ++ ==  +4 as the size of an int is 4 bytes here! And again, after that, the pointer is printed. The last chunk of code goes:
```
│           0x55a93cbe5748      488b45f8       mov rax, qword [var_8h]
│           0x55a93cbe574c      8b00           mov eax, dword [rax]
│           0x55a93cbe574e      89c6           mov esi, eax
│           0x55a93cbe5750      488d3da20000.  lea rdi, [0x55a93cbe57f9] ; "%i\n"
│           0x55a93cbe5757      b800000000     mov eax, 0
│           0x55a93cbe575c      e82ffeffff     call sym.imp.printf     ; int printf(const char *format)
``` 
Finally, the program prints the content of what is pointed by var_8h, but as var_8h was updated, it now points to a different memory address, 4 bytes away from the original, so whatever random stuff will get printed instead of our 3. Debug the program yourself and examine that as an exercise.



That one was very basic, let's move with another very basic example as well, so we can be sure are not missing anything:
```c
#include <stdio.h>
#include <stdlib.h>
 
main() {

int * spoint;


  spoint  = (int *) malloc (sizeof(int));
  *spoint = 3;
  
  
  printf ("%p \n",spoint);
  
  printf ("%d\n",*spoint);
  
  (*spoint) ++;
  
  printf ("%d\n",*spoint);

  
  getchar();
}
```
The difference here is here: (*spoint) ++; be used to that, as if you review C/C++ code or do low level stuff in general you will see it a lot. (*pointer) is used for referencing the actual content of a pointer, so doing that here will actually update spoint and turn that 3 into a 4

Time to debug it, but wait, this program is almost the same as the previous one, it looks like a... "patched version". Patching is very common in modern software, developers patch and redistribute their software and sometimes those patches do tackle security vulnerabilities.

We can use binary diffing to compare those two executables like this:

```
red@blue:~/c/chapter10$ radiff2 -A -a x86  -C ipoint secondpointer
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
                          sym._init  23 0x560 |   MATCH  (1.000000) | 0x560   23 sym._init
                     sym.imp.printf   6 0x590 |   MATCH  (1.000000) | 0x590    6 sym.imp.printf
                    sym.imp.getchar   6 0x5a0 |   MATCH  (1.000000) | 0x5a0    6 sym.imp.getchar
                     sym.imp.malloc   6 0x5b0 |   MATCH  (1.000000) | 0x5b0    6 sym.imp.malloc
                             entry0  42 0x5d0 |   MATCH  (0.952381) | 0x5d0   42 entry0
           sym.deregister_tm_clones  50 0x600 |   MATCH  (1.000000) | 0x600   50 sym.deregister_tm_clones
             sym.register_tm_clones  66 0x640 |   MATCH  (1.000000) | 0x640   66 sym.register_tm_clones
          sym.__do_global_dtors_aux  58 0x690 |   MATCH  (1.000000) | 0x690   58 sym.__do_global_dtors_aux
                        entry.init0  10 0x6d0 |   MATCH  (1.000000) | 0x6d0   10 entry.init0
                               main 147 0x6da |   MATCH  (0.802721) | 0x6da  133 main
                sym.__libc_csu_init 101 0x770 | UNMATCH  (0.970297) | 0x760  101 sym.__libc_csu_init
                sym.__libc_csu_fini   2 0x7e0 |   MATCH  (1.000000) | 0x7d0    2 sym.__libc_csu_fini
                          sym._fini   9 0x7e4 |   MATCH  (1.000000) | 0x7d4    9 sym._fini
loc.imp._ITM_deregisterTMCloneTable 292 0x0 | UNMATCH  (0.993711) | 0x0  292 loc.imp._ITM_deregisterTMCloneTable
red@blue:~/c/chapter10$ 
```
There are many ways to use radiff, we can use it without any kind of arguments and it will just dump the differences, but those can get huge. The output we just generated with -a shows us that the main differences have been encountered mainly on the main function. That is very useful, specially on large programs that have many functions, as for example, the patch may be applied to just one single function, imagine that, we can save a lot of time.

On this case, the difference can be found here:
```
│           0x0000072f      8b00           mov eax, dword [rax]
│           0x00000731      8d5001         lea edx, [rax + 1]
│           0x00000734      488b45f8       mov rax, qword [var_8h]
│           0x00000738      8910           mov dword [rax], edx
│           0x0000073a      488b45f8       mov rax, qword [var_8h]
│           0x0000073e      8b00           mov eax, dword [rax]
│           0x00000740      89c6           mov esi, eax
│           0x00000742      488d3da00000.  lea rdi, [0x000007e9]       ; "%d\n" ; const char *format
│           0x00000749      b800000000     mov eax, 0

```
Here, the content of whats pointed by RAX is moved to eax, a pointer in this case then we load into edx the contents of what is pointed by that pointer (3) +1. As you can see, it plays a "nice game of pointers here" to avoid using add directly. At the end it's the same result.



Let's go for a more complex example now. As you can figure out, pointers can be used along with functions. When we pass an array as an argumente to a function, by the way, it passes a reference (base addr) to the array instead the whole array, so if the array gets updated inside the function those changes will be permament and effective after the ret. Same thing can be done with ints, chars or any kind of variable. We just need to declare those params as pointers with * (or we can also declare them as addresses with & and do the magic inside the func).

```c
#include <stdio.h>
 
void x2(int *x) {
   *x = *x * 2;
}
 
main() {
   int n = 5;   
   printf("value= %d\n", n);
   x2(&n);
   printf("updated_value= %d\n", n);


  
  getchar();
}
```
As this is a bit more complex, we can use agc to generate the call graph at main:
```
[0x562a3106b714]> agc
                                        ┌────────────────────┐
                                        │  main              │
                                        └────────────────────┘
                                              v
                                              │
      ┌───────────────────────────────────────│
      │                         ┌─────────────│
      │                         │             │───────────┐
      │                         │             └─────────────────────────────────────┐
      │                         │                         │                         │
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐    ┌────────────────────────────┐
│  sym.imp.printf    │    │  sym.x2            │    │  sym.imp.getchar   │    │  sym.imp.__stack_chk_fail  │
└────────────────────┘    └────────────────────┘    └────────────────────┘    └────────────────────────────┘
[0x562a3106b714]> 
```
Here we see that the program calls sym.x2 here, noice.

```
[0x562a3106b714]> pdf
            ; DATA XREF from entry0 @ 0x562a3106b60d
┌ 118: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           0x562a3106b714      55             push rbp
│           0x562a3106b715      4889e5         mov rbp, rsp
│           0x562a3106b718      4883ec10       sub rsp, 0x10
│           0x562a3106b71c      64488b042528.  mov rax, qword fs:[0x28]
│           0x562a3106b725      488945f8       mov qword [var_8h], rax
│           0x562a3106b729      31c0           xor eax, eax
│           0x562a3106b72b      c745f4050000.  mov dword [var_ch], 5
│           0x562a3106b732      8b45f4         mov eax, dword [var_ch]
│           0x562a3106b735      89c6           mov esi, eax
│           0x562a3106b737      488d3dd60000.  lea rdi, str.value___d  ; 0x562a3106b814 ; "value= %d\n"
│           0x562a3106b73e      b800000000     mov eax, 0
│           0x562a3106b743      e878feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x562a3106b748      488d45f4       lea rax, [var_ch]
│           0x562a3106b74c      4889c7         mov rdi, rax
│           0x562a3106b74f      e8a6ffffff     call sym.x2
│           0x562a3106b754      8b45f4         mov eax, dword [var_ch]
│           0x562a3106b757      89c6           mov esi, eax
│           0x562a3106b759      488d3dbf0000.  lea rdi, str.updated_value___d ; 0x562a3106b81f ; "updated_value= %d\n"
│           0x562a3106b760      b800000000     mov eax, 0
│           0x562a3106b765      e856feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x562a3106b76a      e861feffff     call sym.imp.getchar    ; int getchar(void)
│           0x562a3106b76f      b800000000     mov eax, 0
│           0x562a3106b774      488b55f8       mov rdx, qword [var_8h]
│           0x562a3106b778      644833142528.  xor rdx, qword fs:[0x28]
│       ┌─< 0x562a3106b781      7405           je 0x562a3106b788
│       │   0x562a3106b783      e828feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x562a3106b788      c9             leave
└           0x562a3106b789      c3             ret
[0x562a3106b714]> 
```
At first, var_ch is initialized with 0x5
```
│           0x562a3106b72b      c745f4050000.  mov dword [var_ch], 5
│           0x562a3106b732      8b45f4         mov eax, dword [var_ch]
```
Then x2 is called like this:
```
│           0x562a3106b748      488d45f4       lea rax, [var_ch]
│           0x562a3106b74c      4889c7         mov rdi, rax
│           0x562a3106b74f      e8a6ffffff     call sym.x2
```
Instead of the value (mov) we use LEA (load effective address) to load var_ch into rdi, so the address (a pointer to) the value holded by var_ch is passed into x2!

We can now look inside x2:

```
[0x562a3106b714]> s sym.x2
[0x562a3106b6fa]> pdf
            ; CALL XREF from main @ 0x562a3106b74f
┌ 26: sym.x2 (int64_t arg1);
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int64_t arg1 @ rdi
│           0x562a3106b6fa      55             push rbp
│           0x562a3106b6fb      4889e5         mov rbp, rsp
│           0x562a3106b6fe      48897df8       mov qword [var_8h], rdi ; arg1
│           0x562a3106b702      488b45f8       mov rax, qword [var_8h]
│           0x562a3106b706      8b00           mov eax, dword [rax]
│           0x562a3106b708      8d1400         lea edx, [rax + rax]
│           0x562a3106b70b      488b45f8       mov rax, qword [var_8h]
│           0x562a3106b70f      8910           mov dword [rax], edx
│           0x562a3106b711      90             nop
│           0x562a3106b712      5d             pop rbp
└           0x562a3106b713      c3             ret
[0x562a3106b6fa]> 
```
Now first the program is loaded from rdi, the value gets loaded inside var_8h a local space reserved inside the function
```
│           0x562a3106b6fe      48897df8       mov qword [var_8h], rdi ; arg1
│           0x562a3106b702      488b45f8       mov rax, qword [var_8h]
```
Then the program multiplies by two, the same way it did in the other example.
```
│           0x562a3106b706      8b00           mov eax, dword [rax]
│           0x562a3106b708      8d1400         lea edx, [rax + rax]
```
And finally, the result of the addition (pointer stored on edx) is moved to the address pointed by the original reference, and the function returns. Try to debug this program as an exercise and appreciate it yourself.

When working with arrays, we can operate the same way. When we declare an array, a static array for example, we are declaring a base addr and some space of type t(int,char, float...) in memory.

That can be interpreted using pointers, like in this program:
```c
#include <stdio.h>
 
main() {
   int data[10];
   int i;
 
     printf ("%p\n", data);
   
    *(data)= 20;
    
     printf ("%d ", *(data));

     *(data+1)= 40;
    
     printf ("%d ", data[1]);
     getchar();
}
```
Here it is:
```
[0x560d6a0d06fa]> pdf
            ; DATA XREF from entry0 @ 0x560d6a0d060d
┌ 137: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_30h @ rbp-0x30
│           ; var int64_t var_2ch @ rbp-0x2c
│           ; var int64_t var_8h @ rbp-0x8
│           0x560d6a0d06fa      55             push rbp
│           0x560d6a0d06fb      4889e5         mov rbp, rsp
│           0x560d6a0d06fe      4883ec30       sub rsp, 0x30
│           0x560d6a0d0702      64488b042528.  mov rax, qword fs:[0x28]
│           0x560d6a0d070b      488945f8       mov qword [var_8h], rax
│           0x560d6a0d070f      31c0           xor eax, eax
│           0x560d6a0d0711      488d45d0       lea rax, [var_30h]
│           0x560d6a0d0715      4889c6         mov rsi, rax
│           0x560d6a0d0718      488d3df50000.  lea rdi, [0x560d6a0d0814] ; "%p\n"
│           0x560d6a0d071f      b800000000     mov eax, 0
│           0x560d6a0d0724      e897feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x560d6a0d0729      c745d0140000.  mov dword [var_30h], 0x14 ; 20
│           0x560d6a0d0730      8b45d0         mov eax, dword [var_30h]
│           0x560d6a0d0733      89c6           mov esi, eax
│           0x560d6a0d0735      488d3ddc0000.  lea rdi, [0x560d6a0d0818] ; "%d "
│           0x560d6a0d073c      b800000000     mov eax, 0
│           0x560d6a0d0741      e87afeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x560d6a0d0746      c745d4280000.  mov dword [var_2ch], 0x28 ; '(' ; 40
│           0x560d6a0d074d      8b45d4         mov eax, dword [var_2ch]
│           0x560d6a0d0750      89c6           mov esi, eax
│           0x560d6a0d0752      488d3dbf0000.  lea rdi, [0x560d6a0d0818] ; "%d "
│           0x560d6a0d0759      b800000000     mov eax, 0
│           0x560d6a0d075e      e85dfeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x560d6a0d0763      e868feffff     call sym.imp.getchar    ; int getchar(void)
│           0x560d6a0d0768      b800000000     mov eax, 0
│           0x560d6a0d076d      488b55f8       mov rdx, qword [var_8h]
│           0x560d6a0d0771      644833142528.  xor rdx, qword fs:[0x28]
│       ┌─< 0x560d6a0d077a      7405           je 0x560d6a0d0781
│       │   0x560d6a0d077c      e82ffeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x560d6a0d0781      c9             leave
└           0x560d6a0d0782      c3             ret
[0x560d6a0d06fa]> 
```
In this program, instead of a base addr and so, the compiler works with two variables, as only two positions get initializied. The first position is initialized at 20:
```
│           0x560d6a0d0729 b    c745d0140000.  mov dword [var_30h], 0x14 ; 20
│           0x560d6a0d0730 b    8b45d0         mov eax, dword [var_30h]
```
We can actually check that by debugging the program like this:
```
[0x560d6a0d0729]> afvd
var var_8h = 0x7ffef51d96a8 = (qword)0x073629ee5f9d1100
var var_30h = 0x7ffef51d9680 = (qword)0x00007fed746809a0
var var_2ch = 0x7ffef51d9684 = (qword)0x0000000000007fed
[0x560d6a0d0729]> 
```
Those are the "variables", after moving after the initialization we see:
```
[0x560d6a0d0729]> ds
[0x560d6a0d0730]> afvd
var var_8h = 0x7ffef51d96a8 = (qword)0x073629ee5f9d1100
var var_30h = 0x7ffef51d9680 = (qword)0x00007fed00000014
var var_2ch = 0x7ffef51d9684 = (qword)0x0000000000007fed
[0x560d6a0d0730]> 
```
Note that, due to the arrays logic: 0x7ffef51d9680 will be the base address of the array, var_2ch will go right after if you note it:

```
│           0x560d6a0d0746      c745d4280000.  mov dword [var_2ch], 0x28 ; '(' ; 40
│           0x560d6a0d074d      8b45d4         mov eax, dword [var_2ch]
```
We can move to the next position, where var_2ch is initialized. As we will see, those vars come one after the other like this:
```
[0x560d6a0d0750]> pf 2i @ 0x7ffef51d9680
0x7ffef51d9680 [0] {
  0x7ffef51d9680 = 20
}
0x7ffef51d9684 [1] {
  0x7ffef51d9684 = 40
}
```
A common way to identify arrays in memory is seeing a lot of vars of the same type that goe one after the other like what we just saw.


And at last but not least, let's work with this final example:

```c
#include <stdio.h>
 
main() {    
   struct person {
     char name[30];
     char email[25];
     int age;
   };
 
   struct person *person1;


   person1 = (struct person*)
     malloc (sizeof(struct person));
   strcpy(person1->name, "Peter");
   strcpy(person1->email, "p@p.p");
   person1->age = 21;

   printf("Person data= %s, %s, and the age is: %d\n",
     person1->name, person1->email, person1->age);
   free(person1);


     getchar();
}
```
On this last example, we are declaring a pointer to a struct, and then we are allocating some space for it on memory with malloc, sizeof works the same way with structs. The compiler will calculate the size of all those fields of the struct and add it together for the malloc call.

Note that we use -> here instead of . as the struct is dynamic.

Show me the disasm!!
```
[0x7fead046c090]> s main
[0x559db307071a]> pdf
            ; DATA XREF from entry0 @ 0x559db307062d
┌ 137: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           0x559db307071a      55             push rbp
│           0x559db307071b      4889e5         mov rbp, rsp
│           0x559db307071e      4883ec10       sub rsp, 0x10
│           0x559db3070722      bf3c000000     mov edi, 0x3c           ; '<' ; 60
│           0x559db3070727      e8c4feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x559db307072c      488945f8       mov qword [var_8h], rax
│           0x559db3070730      488b45f8       mov rax, qword [var_8h]
│           0x559db3070734      c70050657465   mov dword [rax], 0x65746550 ; 'Pete'
│                                                                      ; [0x65746550:4]=-1
│           0x559db307073a      66c740047200   mov word [rax + 4], 0x72 ; 'r'
│                                                                      ; [0x72:2]=0xffff ; 114
│           0x559db3070740      488b45f8       mov rax, qword [var_8h]
│           0x559db3070744      4883c01e       add rax, 0x1e           ; 30
│           0x559db3070748      c7007040702e   mov dword [rax], 0x2e704070 ; 'p@p.'
│                                                                      ; [0x2e704070:4]=-1
│           0x559db307074e      66c740047000   mov word [rax + 4], 0x70 ; 'p'
│                                                                      ; [0x70:2]=0xffff ; 112
│           0x559db3070754      488b45f8       mov rax, qword [var_8h]
│           0x559db3070758      c74038150000.  mov dword [rax + 0x38], 0x15 ; [0x15:4]=-1 ; 21
│           0x559db307075f      488b45f8       mov rax, qword [var_8h]
│           0x559db3070763      8b5038         mov edx, dword [rax + 0x38]
│           0x559db3070766      488b45f8       mov rax, qword [var_8h]
│           0x559db307076a      488d701e       lea rsi, [rax + 0x1e]
│           0x559db307076e      488b45f8       mov rax, qword [var_8h]
│           0x559db3070772      89d1           mov ecx, edx
│           0x559db3070774      4889f2         mov rdx, rsi
│           0x559db3070777      4889c6         mov rsi, rax
│           0x559db307077a      488d3db70000.  lea rdi, str.Person_data___s___s__and_the_age_is:__d ; 0x559db3070838 ; "Person data= %s, %s, and the age is: %d\n"
│           0x559db3070781      b800000000     mov eax, 0
│           0x559db3070786      e845feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x559db307078b      488b45f8       mov rax, qword [var_8h]
│           0x559db307078f      4889c7         mov rdi, rax
│           0x559db3070792      e829feffff     call sym.imp.free       ; void free(void *ptr)
│           0x559db3070797      e844feffff     call sym.imp.getchar    ; int getchar(void)
│           0x559db307079c      b800000000     mov eax, 0
│           0x559db30707a1      c9             leave
└           0x559db30707a2      c3             ret
[0x559db307071a]> 
```
As we can first see, the program declares var_8h as a pointer to the base addr of the struct, then keeps some stack space (0x10) on stack:
```
│           ; var int64_t var_8h @ rbp-0x8
│           0x559db307071a      55             push rbp
│           0x559db307071b      4889e5         mov rbp, rsp
│           0x559db307071e      4883ec10       sub rsp, 0x10
```
Then it allocates 60 bytes on HEAP for the struct with malloc:
```
│           0x559db3070722      bf3c000000     mov edi, 0x3c           ; '<' ; 60
│           0x559db3070727      e8c4feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
```
Then loads the base addr in rax, and copies "Peter" inside. 
```
│           0x559db3070730      488b45f8       mov rax, qword [var_8h]
│           0x559db3070734      c70050657465   mov dword [rax], 0x65746550 ; 'Pete'
│                                                                      ; [0x65746550:4]=-1
│           0x559db307073a      66c740047200   mov word [rax + 4], 0x72 ; 'r'
│                                                                      ; [0x72:2]=0xffff ; 114
```
Look at how the final "r" is loaded after "Pete" (rax+4) as Pete = 4 chars = 4 bytes
```
│           0x559db3070740      488b45f8       mov rax, qword [var_8h]
│           0x559db3070744      4883c01e       add rax, 0x1e           ; 30
│           0x559db3070748      c7007040702e   mov dword [rax], 0x2e704070 ; 'p@p.'
│                                                                      ; [0x2e704070:4]=-1
│           0x559db307074e      66c740047000   mov word [rax + 4], 0x70 ; 'p'
```
Note that add gets added to 0x1e, that is important, as rax holds the base add of that data structure and the first value of that struct is an array of 30 positions of byte, we need to go over it, as the next array will start right after.

```
│           0x559db3070754      488b45f8       mov rax, qword [var_8h]
│           0x559db3070758      c74038150000.  mov dword [rax + 0x38], 0x15 ; [0x15:4]=-1 ; 21
│           0x559db307075f      488b45f8       mov rax, qword [var_8h]
```
And then we have the age int. It follows the same strategy for being initialized.


And thats all for now, compile those programs and reverse them yourself. The next post will be about linked lists and it will be the final post on dynamic memory, then we'll go through some basic stuff like defines, unions and bitwise operations.