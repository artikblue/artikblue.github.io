---
layout: post
title:  Reverse engineering 32 and 64 bits binaries with Radare2 - 10 (pointers and dynamic memory)
tags: reversing c radare
image: '/images//radare2/radare2_10.png'
date: 2020-05-06 15:01:35 -0700
---

Hello I'm Artik Blue and today you will finally understand C pointers.


Let's start with this code
```c
#include <stdio.h>
#include <stdlib.h>

int main(){

    int i = 2;

    char c = 'c';

    char* pc = &c;

    printf("Value of i: %d \n",i);
    printf("Address of i: %p \n",&i);
    printf("Value of c: %c \n", c);
    printf("Address of c: %p \n",&c);

    printf("Updating the content of the mem address pointed by pc \n");

    *pc = 'b';

    printf("Value of c: %c \n", c);

return 0;
}

```
In C &c is used for indicating the address of the variable c. *p indicates a pointer. We can have multiple pointers to the same memory location so if that memory location is updated that will affect all of the pointers. If you have zero knowledge about pointers, have a quick read at this one: https://www.programiz.com/c-programming/c-pointers and then go on with this post.

So when compiled, the program outputs:


```
Value of i: 2 
Address of i: 0x7ffe948d662c 
Value of c: c 
Address of c: 0x7ffe948d662b 
Updating the content of the mem address pointed by pc 
Value of c: b 
```


And now  the disasm:


```
[0x556609210155]> pdf
            ; DATA XREF from entry0 @ 0x55660921008d
┌ 210: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_15h @ rbp-0x15
│           ; var int64_t var_14h @ rbp-0x14
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_8h @ rbp-0x8
│           0x556609210155      55             push rbp
│           0x556609210156      4889e5         mov rbp, rsp
│           0x556609210159      4883ec20       sub rsp, 0x20
│           0x55660921015d      64488b042528.  mov rax, qword fs:[0x28]
│           0x556609210166      488945f8       mov qword [var_8h], rax
│           0x55660921016a      31c0           xor eax, eax
│           0x55660921016c      c745ec020000.  mov dword [var_14h], 2
│           0x556609210173      c645eb63       mov byte [var_15h], 0x63 ; 'c' ; 99
│           0x556609210177      488d45eb       lea rax, [var_15h]
│           0x55660921017b      488945f0       mov qword [var_10h], rax
│           0x55660921017f      8b45ec         mov eax, dword [var_14h]
│           0x556609210182      89c6           mov esi, eax
│           0x556609210184      488d3d7d0e00.  lea rdi, str.Value_of_i:__d ; 0x556609211008 ; "Value of i: %d \n"
│           0x55660921018b      b800000000     mov eax, 0
│           0x556609210190      e8bbfeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x556609210195      488d45ec       lea rax, [var_14h]
│           0x556609210199      4889c6         mov rsi, rax
│           0x55660921019c      488d3d760e00.  lea rdi, str.Address_of_i:__p ; 0x556609211019 ; "Address of i: %p \n"
│           0x5566092101a3      b800000000     mov eax, 0
│           0x5566092101a8      e8a3feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5566092101ad      0fb645eb       movzx eax, byte [var_15h]
│           0x5566092101b1      0fbec0         movsx eax, al
│           0x5566092101b4      89c6           mov esi, eax
│           0x5566092101b6      488d3d6f0e00.  lea rdi, str.Value_of_c:__c ; 0x55660921102c ; "Value of c: %c \n"
│           0x5566092101bd      b800000000     mov eax, 0
│           0x5566092101c2      e889feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5566092101c7      488d45eb       lea rax, [var_15h]
│           0x5566092101cb      4889c6         mov rsi, rax
│           0x5566092101ce      488d3d680e00.  lea rdi, str.Address_of_c:__p ; 0x55660921103d ; "Address of c: %p \n"
│           0x5566092101d5      b800000000     mov eax, 0
│           0x5566092101da      e871feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5566092101df      488d3d6a0e00.  lea rdi, str.Updating_the_content_of_the_mem_address_pointed_by_pc ; 0x556609211050 ; "Updating the content of the mem address pointed by pc "
│           0x5566092101e6      e845feffff     call sym.imp.puts       ; int puts(const char *s)
│           0x5566092101eb      488b45f0       mov rax, qword [var_10h]
│           0x5566092101ef      c60062         mov byte [rax], 0x62    ; 'b'
│                                                                      ; [0x62:1]=255 ; 98
│           0x5566092101f2      0fb645eb       movzx eax, byte [var_15h]
│           0x5566092101f6      0fbec0         movsx eax, al
│           0x5566092101f9      89c6           mov esi, eax
│           0x5566092101fb      488d3d2a0e00.  lea rdi, str.Value_of_c:__c ; 0x55660921102c ; "Value of c: %c \n"
│           0x556609210202      b800000000     mov eax, 0
│           0x556609210207      e844feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55660921020c      b800000000     mov eax, 0
│           0x556609210211      488b55f8       mov rdx, qword [var_8h]
│           0x556609210215      644833142528.  xor rdx, qword fs:[0x28]
│       ┌─< 0x55660921021e      7405           je 0x556609210225
│       │   0x556609210220      e81bfeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x556609210225      c9             leave
└           0x556609210226      c3             ret
[0x556609210155]> 
```
Hey ho! Let's dissect that. At first the program initializes those variables:
```
│           0x55660921016c      c745ec020000.  mov dword [var_14h], 2
│           0x556609210173      c645eb63       mov byte [var_15h], 0x63 ; 'c' ; 99
│           0x556609210177      488d45eb       lea rax, [var_15h]
│           0x55660921017b      488945f0       mov qword [var_10h], rax
```
So the first var is being initialized with 2, then another var is initialized with 0x63 or char C and then the memory address of (lea = load effective address) that var  and not the content is being passed to var_10h. As we are almost sure that those first vars are related the i int and the c char, we can rename it using afvn, so for now the thing will look like:
```
[0x556609210155]> afv
var int64_t char_c @ rbp-0x15
var int64_t int_i @ rbp-0x14
var int64_t var_10h @ rbp-0x10
var int64_t var_8h @ rbp-0x8 = stack cookie
```
And as var_10h will hold the ADDRESS of c we can rename it as pointer_c
```
[0x556609210155]> afvn pointer_c var_10h
[0x556609210155]> afv
var int64_t char_c @ rbp-0x15
var int64_t int_i @ rbp-0x14
var int64_t pointer_c @ rbp-0x10
var int64_t var_8h @ rbp-0x8
```
Let's inspect the first printf
```
│           0x55660921017f      8b45ec         mov eax, dword [int_i]
│           0x556609210182      89c6           mov esi, eax
│           0x556609210184      488d3d7d0e00.  lea rdi, str.Value_of_i:__d ; 0x556609211008 ; "Value of i: %d \n"
│           0x55660921018b      b800000000     mov eax, 0
│           0x556609210190      e8bbfeffff     call sym.imp.printf     ; int printf(const char *format)
```
Nothing new here, by "[ref]" we indicate that we want the content of whats pointed by int_i, so the value of the i var, we load it in eax (we don't use rax cause we have enough space using eax only), then we load base address of the string to print "Value of..." as a parameter as well. The printf function will take those two params and do its magic as we already should know. Just note that on this first case, we are passing the value of the variable, instead of its address. Let's move on:
```
│           0x556609210195      488d45ec       lea rax, [int_i]
│           0x556609210199      4889c6         mov rsi, rax
│           0x55660921019c      488d3d760e00.  lea rdi, str.Address_of_i:__p ; 0x556609211019 ; "Address of i: %p \n"
│           0x5566092101a3      b800000000     mov eax, 0
│           0x5566092101a8      e8a3feffff     call sym.imp.printf     ; int printf(const char *format)
```
Just look how on this next block the progam does lea instead of mov. This time, the program loads the ADDRESS of int_i instead of the value located at whats pointed by int_i. So in general terms using &var internally translates to lea reg, "[var]". This is a key concept in reverse engineering, exploit development and in general terms anything related to low level program analysis, you should have it very clear.
Let's proceed
```
│           0x5566092101ad      0fb645eb       movzx eax, byte [char_c]
│           0x5566092101b1      0fbec0         movsx eax, al
│           0x5566092101b4      89c6           mov esi, eax
│           0x5566092101b6      488d3d6f0e00.  lea rdi, str.Value_of_c:__c ; 0x55660921102c ; "Value of c: %c \n"
│           0x5566092101bd      b800000000     mov eax, 0
│           0x5566092101c2      e889feffff     call sym.imp.printf     ; int printf(const char *format)
```
Nothing worth commenting here, the VALUE is loaded, movzx is used for mem optimization.
```
│           0x5566092101c7      488d45eb       lea rax, [char_c]
│           0x5566092101cb      4889c6         mov rsi, rax
│           0x5566092101ce      488d3d680e00.  lea rdi, str.Address_of_c:__p ; 0x55660921103d ; "Address of c: %p \n"
│           0x5566092101d5      b800000000     mov eax, 0
│           0x5566092101da      e871feffff     call sym.imp.printf     ; int printf(const char *format)
```
Then, again, the ADDRESS is loaded this time.

But at the end of the program we have this:
```
│           0x5566092101eb      488b45f0       mov rax, qword [pointer_c]
│           0x5566092101ef      c60062         mov byte [rax], 0x62    ; 'b'
│                                                                      ; [0x62:1]=255 ; 98
│           0x5566092101f2      0fb645eb       movzx eax, byte [char_c]
│           0x5566092101f6      0fbec0         movsx eax, al
│           0x5566092101f9      89c6           mov esi, eax
│           0x5566092101fb      488d3d2a0e00.  lea rdi, str.Value_of_c:__c ; 0x55660921102c ; "Value of c: %c \n"
│           0x556609210202      b800000000     mov eax, 0
│           0x556609210207      e844feffff     call sym.imp.printf     ; int printf(const char *format)
```
What happens here? The contents of pointer_c are moved to eax, then the content of what is pointed by eax is updated with 'b' and then we forget about pointer_c and we just printf what is pointed by char_c (???) Debuging is quite useful for understanding what is happening here.

So we start like this:
```
│           0x5566092101eb b    488b45f0       mov rax, qword [pointer_c]
│           0x5566092101ef      c60062         mov byte [rax], 0x62    ; 'b'
│                                                                      ; [0x62:1]=255 ; 98
│           0x5566092101f2      0fb645eb       movzx eax, byte [char_c]
│           0x5566092101f6      0fbec0         movsx eax, al
│           0x5566092101f9      89c6           mov esi, eax
│           0x5566092101fb      488d3d2a0e00.  lea rdi, str.Value_of_c:__c ; 0x55660921102c ; "Value of c: %c \n"
│           0x556609210202      b800000000     mov eax, 0
│           0x556609210207      e844feffff     call sym.imp.printf     ; int printf(const char *format)
[...]
[0x5566092101eb]> afvd
var var_8h = 0x7ffd71635228 = (qword)0xa0af6487b4e4ef00
var int_i = 0x7ffd7163521c = (qword)0x7163521b00000002
var char_c = 0x7ffd7163521b = (qword)0x63521b0000000263
var pointer_c = 0x7ffd71635220 = (qword)0x00007ffd7163521b
```
As you can see, the content of pointer_c (0x00007ffd7163521b) is the mem address of char_c (0x7ffd7163521b) this is how pointers work, pointers store memory addresses.

So after we do the first mov, rax will look like this:
```
[0x5566092101eb]> ds
[0x5566092101ef]> dr rax
0x7ffd7163521b
```
Now rax holds the CONTENT of pointer_c and the content of pointer_c is the ADDRESS of char c, so doing "[rax]" is the same as doing "[char_c]". And char_c contains a 'c' char:
```
[0x5566092101ef]> afvd
var var_8h = 0x7ffd71635228 = (qword)0xa0af6487b4e4ef00
var int_i = 0x7ffd7163521c = (qword)0x7163521b00000002
var char_c = 0x7ffd7163521b = (qword)0x63521b0000000263
var pointer_c = 0x7ffd71635220 = (qword)0x00007ffd7163521b

[0x5566092101ef]> pxw @ 0x7ffd7163521b
0x7ffd7163521b  0x00000263 0x63521b00 0x007ffd71 0xe4ef0000  c.....Rcq.......
```
And after doing the second mov
```
[0x5566092101ef]> ds
[0x5566092101f2]> pxw @ 0x7ffd7163521b
0x7ffd7163521b  0x00000262 0x63521b00 0x007ffd71 0xe4ef0000  b.....Rcq.......
```
Now it contains a 'b' char.

Then the program continues, this time it loads char_c but that's ok cause the address of char_c is the same as "[rax]" or "[pointer_c]"!

And we are done with this first example, let's move on with something more complex but easy as well :)


Remember the program we did on one of the past tutorials? The one that was related to an array that needed to be filled by a user in a while loop. Let's inspect this one:
```C
#include <stdio.h>
 
main() {
  int data[100];      
  int entered;    
  int i;           
  long sum=0;     
 
  do {
    printf("How many numbers? ");
    scanf("%d", &entered);
    if (entered>100)  
      printf("Limit is 100");
  } while (entered>100);  
 
  
  for (i=0; i<entered; i++) {
    printf("Enter number %d: ", i+1);
    scanf("%d", &data[i]);
  }
 
  
  for (i=0; i<entered; i++) 
    sum += data[i];
 
  printf("SUM: %ld\n", sum);
}
```
We should already know how the program works, no mystery, no pointers used here, just static memory. Let's see:
```
[0x55c2a9231155]> pdf
            ; DATA XREF from entry0 @ 0x55c2a923108d
┌ 335: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_1b0h @ rbp-0x1b0
│           ; var int64_t var_1ach @ rbp-0x1ac
│           ; var int64_t var_1a8h @ rbp-0x1a8
│           ; var int64_t var_1a0h @ rbp-0x1a0
│           ; var int64_t var_8h @ rbp-0x8
│           0x55c2a9231155      55             push rbp
│           0x55c2a9231156      4889e5         mov rbp, rsp
│           0x55c2a9231159      4881ecb00100.  sub rsp, 0x1b0
│           0x55c2a9231160      64488b042528.  mov rax, qword fs:[0x28]
│           0x55c2a9231169      488945f8       mov qword [var_8h], rax
│           0x55c2a923116d      31c0           xor eax, eax
│           0x55c2a923116f      48c78558feff.  mov qword [var_1a8h], 0
│       ┌─> 0x55c2a923117a      488d3d830e00.  lea rdi, str.How_many_numbers ; 0x55c2a9232004 ; "How many numbers? "
│       ╎   0x55c2a9231181      b800000000     mov eax, 0
│       ╎   0x55c2a9231186      e8b5feffff     call sym.imp.printf     ; int printf(const char *format)
│       ╎   0x55c2a923118b      488d8550feff.  lea rax, [var_1b0h]
│       ╎   0x55c2a9231192      4889c6         mov rsi, rax
│       ╎   0x55c2a9231195      488d3d7b0e00.  lea rdi, [0x55c2a9232017] ; "%d"
│       ╎   0x55c2a923119c      b800000000     mov eax, 0
│       ╎   0x55c2a92311a1      e8aafeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│       ╎   0x55c2a92311a6      8b8550feffff   mov eax, dword [var_1b0h]
│       ╎   0x55c2a92311ac      83f864         cmp eax, 0x64           ; 100
│      ┌──< 0x55c2a92311af      7e11           jle 0x55c2a92311c2
│      │╎   0x55c2a92311b1      488d3d620e00.  lea rdi, str.Limit_is_100 ; 0x55c2a923201a ; "Limit is 100"
│      │╎   0x55c2a92311b8      b800000000     mov eax, 0
│      │╎   0x55c2a92311bd      e87efeffff     call sym.imp.printf     ; int printf(const char *format)
│      └──> 0x55c2a92311c2      8b8550feffff   mov eax, dword [var_1b0h]
│       ╎   0x55c2a92311c8      83f864         cmp eax, 0x64           ; 100
│       └─< 0x55c2a92311cb      7fad           jg 0x55c2a923117a
│           0x55c2a92311cd      c78554feffff.  mov dword [var_1ach], 0
│       ┌─< 0x55c2a92311d7      eb4e           jmp 0x55c2a9231227
│      ┌──> 0x55c2a92311d9      8b8554feffff   mov eax, dword [var_1ach]
│      ╎│   0x55c2a92311df      83c001         add eax, 1
│      ╎│   0x55c2a92311e2      89c6           mov esi, eax
│      ╎│   0x55c2a92311e4      488d3d3c0e00.  lea rdi, str.Enter_number__d: ; 0x55c2a9232027 ; "Enter number %d: "
│      ╎│   0x55c2a92311eb      b800000000     mov eax, 0
│      ╎│   0x55c2a92311f0      e84bfeffff     call sym.imp.printf     ; int printf(const char *format)
│      ╎│   0x55c2a92311f5      488d8560feff.  lea rax, [var_1a0h]
│      ╎│   0x55c2a92311fc      8b9554feffff   mov edx, dword [var_1ach]
│      ╎│   0x55c2a9231202      4863d2         movsxd rdx, edx
│      ╎│   0x55c2a9231205      48c1e202       shl rdx, 2
│      ╎│   0x55c2a9231209      4801d0         add rax, rdx
│      ╎│   0x55c2a923120c      4889c6         mov rsi, rax
│      ╎│   0x55c2a923120f      488d3d010e00.  lea rdi, [0x55c2a9232017] ; "%d"
│      ╎│   0x55c2a9231216      b800000000     mov eax, 0
│      ╎│   0x55c2a923121b      e830feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      ╎│   0x55c2a9231220      838554feffff.  add dword [var_1ach], 1
│      ╎│   ; CODE XREF from main @ 0x55c2a92311d7
│      ╎└─> 0x55c2a9231227      8b8550feffff   mov eax, dword [var_1b0h]
│      ╎    0x55c2a923122d      398554feffff   cmp dword [var_1ach], eax
│      └──< 0x55c2a9231233      7ca4           jl 0x55c2a92311d9
│           0x55c2a9231235      c78554feffff.  mov dword [var_1ach], 0
│       ┌─< 0x55c2a923123f      eb1f           jmp 0x55c2a9231260
│      ┌──> 0x55c2a9231241      8b8554feffff   mov eax, dword [var_1ach]
│      ╎│   0x55c2a9231247      4898           cdqe
│      ╎│   0x55c2a9231249      8b848560feff.  mov eax, dword [rbp + rax*4 - 0x1a0]
│      ╎│   0x55c2a9231250      4898           cdqe
│      ╎│   0x55c2a9231252      48018558feff.  add qword [var_1a8h], rax
│      ╎│   0x55c2a9231259      838554feffff.  add dword [var_1ach], 1
│      ╎│   ; CODE XREF from main @ 0x55c2a923123f
│      ╎└─> 0x55c2a9231260      8b8550feffff   mov eax, dword [var_1b0h]
│      ╎    0x55c2a9231266      398554feffff   cmp dword [var_1ach], eax
│      └──< 0x55c2a923126c      7cd3           jl 0x55c2a9231241
│           0x55c2a923126e      488b8558feff.  mov rax, qword [var_1a8h]
│           0x55c2a9231275      4889c6         mov rsi, rax
│           0x55c2a9231278      488d3dba0d00.  lea rdi, str.SUM:__ld   ; 0x55c2a9232039 ; "SUM: %ld\n"
│           0x55c2a923127f      b800000000     mov eax, 0
│           0x55c2a9231284      e8b7fdffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55c2a9231289      b800000000     mov eax, 0
│           0x55c2a923128e      488b4df8       mov rcx, qword [var_8h]
│           0x55c2a9231292      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x55c2a923129b      7405           je 0x55c2a92312a2
│       │   0x55c2a923129d      e88efdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55c2a92312a2      c9             leave
└           0x55c2a92312a3      c3             ret
[0x55c2a9231155]> 
```
What I want you to note here is the following, at the very beginning of the code you see this = 432:
```
│           0x55c2a9231159      4881ecb00100.  sub rsp, 
```
You should have seen instructions like this one in many of the binaries we analyzed during our journey. What this does is basically keep some memory space in the local memory related to the function (using the stack) to hold local variables. 
(check this https://en.wikibooks.org/wiki/X86_Disassembly/Functions_and_Stack_Frames)

And this time in here it looks like it keeps a bit more than 400 bytes. If you think about it, it makes sense as according to the code, we are declaring an array of 100 ints, assuming 4 bytes per int, those 400 bytes and more make sense. It is very common to see the program keeping a bit more space than the initially needed. Watching this sub rbp at the very beginning of the function will reveal interesting information.

I'm not going to enter into a lot of details on the code, as there is almost nothing new here, you should know how to analyze it very well

What I want to note this time is the following. In this program, we are using a do-while instead of a while, we can see that here:
```
│       ┌─> 0x55c2a923117a      488d3d830e00.  lea rdi, str.How_many_numbers ; 0x55c2a9232004 ; "How many numbers? "
│       ╎   0x55c2a9231181      b800000000     mov eax, 0
│       ╎   0x55c2a9231186      e8b5feffff     call sym.imp.printf     ; int printf(const char *format)
│       ╎   0x55c2a923118b      488d8550feff.  lea rax, [var_1b0h]
│       ╎   0x55c2a9231192      4889c6         mov rsi, rax
│       ╎   0x55c2a9231195      488d3d7b0e00.  lea rdi, [0x55c2a9232017] ; "%d"
│       ╎   0x55c2a923119c      b800000000     mov eax, 0
│       ╎   0x55c2a92311a1      e8aafeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│       ╎   0x55c2a92311a6      8b8550feffff   mov eax, dword [var_1b0h]
│       ╎   0x55c2a92311ac      83f864         cmp eax, 0x64           ; 100
│      ┌──< 0x55c2a92311af      7e11           jle 0x55c2a92311c2
│      │╎   0x55c2a92311b1      488d3d620e00.  lea rdi, str.Limit_is_100 ; 0x55c2a923201a ; "Limit is 100"
│      │╎   0x55c2a92311b8      b800000000     mov eax, 0
│      │╎   0x55c2a92311bd      e87efeffff     call sym.imp.printf     ; int printf(const char *format)
│      └──> 0x55c2a92311c2      8b8550feffff   mov eax, dword [var_1b0h]
│       ╎   0x55c2a92311c8      83f864         cmp eax, 0x64           ; 100
│       └─< 0x55c2a92311cb      7fad           jg 0x55c2a923117a

```
As you see, the block of code is executed at first, then after that the condition check (cmp 100) is done and the program jumps back to the top of the code or just goes on, but the block of code is executed min once. If we do a while instad of a do while, as we know, the program will jump and do the cmp, then will go to the while block of code or not based on the cmp.

The rest of the program is no mystery, let's move on and inspect the same program but this time using dynamic memory:

```C
#include <stdio.h>
#include <stdlib.h>
 
main() {
  int* data;      
  int valnum;    
  int i;          
  long sum=0;     

  do {
    printf("How many vals you need to add? ");
    scanf("%d", &valnum);
    data = (int *) malloc (valnum * sizeof(int));
    if (data == NULL)  
      printf("NO SPACE AVAILABLE.");
  } while (data == NULL); 


  for (i=0; i<valnum; i++) {
    printf("ENTER NUM %d ", i+1);
    scanf("%d", data+i);
  }
 

  for (i=0; i<valnum; i++) 
    sum += *(data+i);
 
  printf("SUM: %ld\n", sum);
  free(data);
}
```
This is new! So the program at first, will ask the user how many values it wants to add, then it will do this:

```
data = (int *) malloc (valnum * sizeof(int));
```
We can break that in parts for a better understanding. At first we do valnum * sizeof(int), sizeof(int) will return the size of an int in bytes in our system ex: 4, then it will be multiplied by valnum, the user input (how many values do you want to add), so if the user wants 4 values it will do something like 4*4 = 16 bytes, the space needed for allocating 4 ints, you got it, right? Then, that will be passed to malloc. This function is used for allocating space in memory. void *malloc(size_t size) allocates the requested memory (heap) and returns a pointer to it(stack) (or NULL if the request fails), that is why the result of malloc is stored in a pointer to int!

Then the program does the following:
```
scanf("%d", data+i);
```
Note that normally when using scan we pass in &var, this time we are just passing data+i, being i an integer (1,2.3...), that is why data is a pointer itself, a memory address, so using & won't make sense here, +i is used here to indicate the next memory address available as data is a pointer to the base addr of that dynamic array.

Then the same logic follows when doing the sum
```
sum += *(data+i);
```
Let's now disasm this program and analyze it:
```
[0x558471c62175]> pdf
            ; DATA XREF from entry0 @ 0x558471c620ad
┌ 322: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_1ch @ rbp-0x1c
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_8h @ rbp-0x8
│           0x558471c62175      55             push rbp
│           0x558471c62176      4889e5         mov rbp, rsp
│           0x558471c62179      4883ec20       sub rsp, 0x20
│           0x558471c6217d      64488b042528.  mov rax, qword fs:[0x28]
│           0x558471c62186      488945f8       mov qword [var_8h], rax
│           0x558471c6218a      31c0           xor eax, eax
│           0x558471c6218c      48c745e80000.  mov qword [var_18h], 0
│       ┌─> 0x558471c62194      488d3d6d0e00.  lea rdi, str.How_many_vals_you_need_to_add ; 0x558471c63008 ; "How many vals you need to add? "
│       ╎   0x558471c6219b      b800000000     mov eax, 0
│       ╎   0x558471c621a0      e8abfeffff     call sym.imp.printf     ; int printf(const char *format)
│       ╎   0x558471c621a5      488d45e0       lea rax, [var_20h]
│       ╎   0x558471c621a9      4889c6         mov rsi, rax
│       ╎   0x558471c621ac      488d3d750e00.  lea rdi, [0x558471c63028] ; "%d"
│       ╎   0x558471c621b3      b800000000     mov eax, 0
│       ╎   0x558471c621b8      e8b3feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│       ╎   0x558471c621bd      8b45e0         mov eax, dword [var_20h]
│       ╎   0x558471c621c0      4898           cdqe
│       ╎   0x558471c621c2      48c1e002       shl rax, 2
│       ╎   0x558471c621c6      4889c7         mov rdi, rax
│       ╎   0x558471c621c9      e892feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│       ╎   0x558471c621ce      488945f0       mov qword [var_10h], rax
│       ╎   0x558471c621d2      48837df000     cmp qword [var_10h], 0
│      ┌──< 0x558471c621d7      7511           jne 0x558471c621ea
│      │╎   0x558471c621d9      488d3d4b0e00.  lea rdi, str.NO_SPACE_AVAILABLE. ; 0x558471c6302b ; "NO SPACE AVAILABLE."
│      │╎   0x558471c621e0      b800000000     mov eax, 0
│      │╎   0x558471c621e5      e866feffff     call sym.imp.printf     ; int printf(const char *format)
│      └──> 0x558471c621ea      48837df000     cmp qword [var_10h], 0
│       └─< 0x558471c621ef      74a3           je 0x558471c62194
│           0x558471c621f1      c745e4000000.  mov dword [var_1ch], 0
│       ┌─< 0x558471c621f8      eb45           jmp 0x558471c6223f
│      ┌──> 0x558471c621fa      8b45e4         mov eax, dword [var_1ch]
│      ╎│   0x558471c621fd      83c001         add eax, 1
│      ╎│   0x558471c62200      89c6           mov esi, eax
│      ╎│   0x558471c62202      488d3d360e00.  lea rdi, str.ENTER_NUM__d ; 0x558471c6303f ; "ENTER NUM %d "
│      ╎│   0x558471c62209      b800000000     mov eax, 0
│      ╎│   0x558471c6220e      e83dfeffff     call sym.imp.printf     ; int printf(const char *format)
│      ╎│   0x558471c62213      8b45e4         mov eax, dword [var_1ch]
│      ╎│   0x558471c62216      4898           cdqe
│      ╎│   0x558471c62218      488d14850000.  lea rdx, [rax*4]
│      ╎│   0x558471c62220      488b45f0       mov rax, qword [var_10h]
│      ╎│   0x558471c62224      4801d0         add rax, rdx
│      ╎│   0x558471c62227      4889c6         mov rsi, rax
│      ╎│   0x558471c6222a      488d3df70d00.  lea rdi, [0x558471c63028] ; "%d"
│      ╎│   0x558471c62231      b800000000     mov eax, 0
│      ╎│   0x558471c62236      e835feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      ╎│   0x558471c6223b      8345e401       add dword [var_1ch], 1
│      ╎│   ; CODE XREF from main @ 0x558471c621f8
│      ╎└─> 0x558471c6223f      8b45e0         mov eax, dword [var_20h]
│      ╎    0x558471c62242      3945e4         cmp dword [var_1ch], eax
│      └──< 0x558471c62245      7cb3           jl 0x558471c621fa
│           0x558471c62247      c745e4000000.  mov dword [var_1ch], 0
│       ┌─< 0x558471c6224e      eb20           jmp 0x558471c62270
│      ┌──> 0x558471c62250      8b45e4         mov eax, dword [var_1ch]
│      ╎│   0x558471c62253      4898           cdqe
│      ╎│   0x558471c62255      488d14850000.  lea rdx, [rax*4]
│      ╎│   0x558471c6225d      488b45f0       mov rax, qword [var_10h]
│      ╎│   0x558471c62261      4801d0         add rax, rdx
│      ╎│   0x558471c62264      8b00           mov eax, dword [rax]
│      ╎│   0x558471c62266      4898           cdqe
│      ╎│   0x558471c62268      480145e8       add qword [var_18h], rax
│      ╎│   0x558471c6226c      8345e401       add dword [var_1ch], 1
│      ╎│   ; CODE XREF from main @ 0x558471c6224e
│      ╎└─> 0x558471c62270      8b45e0         mov eax, dword [var_20h]
│      ╎    0x558471c62273      3945e4         cmp dword [var_1ch], eax
│      └──< 0x558471c62276      7cd8           jl 0x558471c62250
│           0x558471c62278      488b45e8       mov rax, qword [var_18h]
│           0x558471c6227c      4889c6         mov rsi, rax
│           0x558471c6227f      488d3dc70d00.  lea rdi, str.SUM:__ld   ; 0x558471c6304d ; "SUM: %ld\n"
│           0x558471c62286      b800000000     mov eax, 0
│           0x558471c6228b      e8c0fdffff     call sym.imp.printf     ; int printf(const char *format)
│           0x558471c62290      488b45f0       mov rax, qword [var_10h]
│           0x558471c62294      4889c7         mov rdi, rax
│           0x558471c62297      e894fdffff     call sym.imp.free       ; void free(void *ptr)
│           0x558471c6229c      b800000000     mov eax, 0
│           0x558471c622a1      488b4df8       mov rcx, qword [var_8h]
│           0x558471c622a5      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x558471c622ae      7405           je 0x558471c622b5
│       │   0x558471c622b0      e88bfdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x558471c622b5      c9             leave
└           0x558471c622b6      c3             ret
[0x558471c62175]> 
```
The malloc is first done here:
```
│       ╎   0x558471c621b8      e8b3feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│       ╎   0x558471c621bd      8b45e0         mov eax, dword [var_20h]
│       ╎   0x558471c621c0      4898           cdqe
│       ╎   0x558471c621c2      48c1e002       shl rax, 2
│       ╎   0x558471c621c6      4889c7         mov rdi, rax
│       ╎   0x558471c621c9      e892feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
```
So, we load the user input (var_20h) in eax, and we multiply it with 4 with shl rax, 2. As we see, sizeof is not called here, that is because the compiler already knows the size of an int. So the user input * 4 is passed to malloc. Let's actually run that.
```
│       ╎   0x558471c621ce b    488945f0       mov qword [var_10h], rax
│       ╎   0x558471c621d2      48837df000     cmp qword [var_10h], 0
│      ┌──< 0x558471c621d7      7511           jne 0x558471c621ea
│      │╎   0x558471c621d9      488d3d4b0e00.  lea rdi, str.NO_SPACE_AVAILABLE. ; 0x558471c6302b ; "NO SPACE AVAILABLE."
│      │╎   0x558471c621e0      b800000000     mov eax, 0
│      │╎   0x558471c621e5      e866feffff     call sym.imp.printf     ; int printf(const char *format)


[0x558471c621ce]> dr rax
0x5584735cfa80

[0x558471c621ce]> dmhg

Heap Layout
┌────────────────────────────────────┐
│    Malloc chunk @ 0x5584735cf250   │
│ size: 0x410 status: allocated      │
└────────────────────────────────────┘
    v
    │
    │
┌────────────────────────────────────┐
│    Malloc chunk @ 0x5584735cf660   │
│ size: 0x410 status: allocated      │
└────────────────────────────────────┘
    v
    │
    │
┌────────────────────────────────────┐
│    Malloc chunk @ 0x5584735cfa70   │
│ size: 0x20 status: allocated       │
└────────────────────────────────────┘
    v
    │
    └──┐
       │
   ┌───────────────────────────────┐
   │  Top chunk @ 0x5584735cfa90   │
   └───────────────────────────────┘

[0x558471c621ce]> 
```
Nice, the function returned a pointer there and some heap space has been created! Then the pointer is saved to var_10h
```
│       ╎   0x558471c621ce b    488945f0       mov qword [var_10h], rax
│       ╎   0x558471c621d2      48837df000     cmp qword [var_10h], 0
```
Let's now watch how the memory manipulation for the user input is done:
```
│      ╎│   0x558471c62213      8b45e4         mov eax, dword [var_1ch]
│      ╎│   0x558471c62216      4898           cdqe
│      ╎│   0x558471c62218      488d14850000.  lea rdx, [rax*4]
│      ╎│   0x558471c62220      488b45f0       mov rax, qword [var_10h]
│      ╎│   0x558471c62224      4801d0         add rax, rdx
│      ╎│   0x558471c62227      4889c6         mov rsi, rax
│      ╎│   0x558471c6222a      488d3df70d00.  lea rdi, [0x558471c63028] ; "%d"
│      ╎│   0x558471c62231      b800000000     mov eax, 0
│      ╎│   0x558471c62236      e835feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
```
Assuming that var_1ch is the loop counter, we see how it gets moved to eax and then THE CONTENT of rax*4 is loaded into rdx and added to the base addr of the dyn array, being 4 the size of the int it makes all the sense, the counter will go 4 by 4 up the dynamic array and assign the new values right there! Then the address related to there will be passed to scanf

The next block of code calculates the sum. Based on what we know, this shoul not be a mystery:
```
│      ┌──> 0x558471c62250      8b45e4         mov eax, dword [var_1ch]
│      ╎│   0x558471c62253      4898           cdqe
│      ╎│   0x558471c62255      488d14850000.  lea rdx, [rax*4]
│      ╎│   0x558471c6225d      488b45f0       mov rax, qword [var_10h]
│      ╎│   0x558471c62261      4801d0         add rax, rdx
│      ╎│   0x558471c62264      8b00           mov eax, dword [rax]
│      ╎│   0x558471c62266      4898           cdqe
│      ╎│   0x558471c62268      480145e8       add qword [var_18h], rax
│      ╎│   0x558471c6226c      8345e401       add dword [var_1ch], 1
```
Same thing is done but this time var_18h is used for storing the sum.

At the end of the program free is called. I like this answer of stack overflow:  https://stackoverflow.com/questions/14986543/calling-free-in-c

In general terms calling free will tell the program that this area of memory can now be used for writting new memory. If a developer does not use free after malloc, and then uses malloc multiple times again, the program memory will grow and grow and that may cause a lot of performance issues and even security problems.

```
│           0x558471c62290      488b45f0       mov rax, qword [var_10h]
│           0x558471c62294      4889c7         mov rdi, rax
│           0x558471c62297      e894fdffff     call sym.imp.free       ; void free(void *ptr)
```
Just note that we pass the base addr of our dyn array to free.