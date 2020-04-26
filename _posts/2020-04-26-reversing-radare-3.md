---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 3 (funcs, cases and loops)"
author: artikblue
categories: [ reversing, course ]
tags: [reversing, c, radare]
image: assets/images/radare2/radare2_2.png
description: "Reverse engineering (C) 32 and 64 bits binaries with radare2."
---

Here we go again. In the previous chapter of this radare2 full course, we walked through the very basic structure of an executable binary written in C paying atention to input/output function calls such as printf and basic data structures such as variables basic measures of controling the execution flow such as if - else statements were reviewed as well. Today were are going a bit deeper with those measures of execution flow control, we'll present the basic usage of the case statement, we'll declare and use functions of our own and at the end we will analyse loops with while and for. 
  
Let's refresh some previous concepts a little bit with the following code, that declares a function for detecting positive numbers and jumps to it.


```
#include <stdio.h>

func2(){
int num;
printf("Enter a number: ");
scanf("%d", &num);

if(num>0) printf("The number is positive.\n");

getchar();
}

main(){

func2();
getchar();

}
```

We can compile that code and jump to it in radare2

```
[0x000006a0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[0x000006a0]> 
```

After running the initial afl, this time here we can detect a couple of interesting places to look at. We have the sym.main as usual, but this time we also have the sym.func2 which looks not so normal, so it may be interesting to look at it. Another initial hints we get here are the presence off scanf, getchar, printf or puts that offer a general idea on what the program must do.

```
[0x000006a0]> afl
0x00000000    3 72   -> 73   sym.imp.__libc_start_main
0x00000618    3 23           sym._init
0x00000640    1 6            sym.imp.puts
0x00000650    1 6            sym.imp.__stack_chk_fail
0x00000660    1 6            sym.imp.printf
0x00000670    1 6            sym.imp.getchar
0x00000680    1 6            sym.imp.__isoc99_scanf
0x00000690    1 6            sub.__cxa_finalize_248_690
0x000006a0    1 43           entry0
0x000006d0    4 50   -> 40   sym.deregister_tm_clones
0x00000710    4 66   -> 57   sym.register_tm_clones
0x00000760    4 49           sym.__do_global_dtors_aux
0x000007a0    1 10           entry1.init
0x000007aa    5 111          sym.func2
0x00000819    1 26           sym.main
0x00000840    4 101          sym.__libc_csu_init
0x000008b0    1 2            sym.__libc_csu_fini
0x000008b4    1 9            sym._fini
[0x000006a0]> 

```
We start by jumping into the main function:
```
[0x000006a0]> s main
[0x00000819]> pdb
            ;-- main:
/ (fcn) sym.main 26
|   sym.main ();
|              ; DATA XREF from 0x000006bd (entry0)
|           0x00000819      55             push rbp
|           0x0000081a      4889e5         mov rbp, rsp
|           0x0000081d      b800000000     mov eax, 0
|           0x00000822      e883ffffff     call sym.func2
|           0x00000827      e844feffff     call sym.imp.getchar        ; int getchar(void)
|           0x0000082c      b800000000     mov eax, 0
|           0x00000831      5d             pop rbp
\           0x00000832      c3             ret
[0x00000819]> 
```
So basically this main function performs the basic stack alignment operations and rapidly jumps to the func2 function, after running it it calls getchar() probably for maintaining the window open (if the program is for example run under windows)
  
So the interesting function here is the func2, let's go there.

```
[0x00000819]> s sym.func2
[0x000007aa]> pdf
/ (fcn) sym.func2 111
|   sym.func2 ();
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x00000822 (sym.main)
|           0x000007aa      55             push rbp
|           0x000007ab      4889e5         mov rbp, rsp
|           0x000007ae      4883ec10       sub rsp, 0x10
|           0x000007b2      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x1a08 ; '('
|           0x000007bb      488945f8       mov qword [local_8h], rax
|           0x000007bf      31c0           xor eax, eax
|           0x000007c1      488d3dfc0000.  lea rdi, qword str.Enter_a_number: ; 0x8c4 ; "Enter a number: "
|           0x000007c8      b800000000     mov eax, 0
|           0x000007cd      e88efeffff     call sym.imp.printf         ; int printf(const char *format)
|           0x000007d2      488d45f4       lea rax, qword [local_ch]
|           0x000007d6      4889c6         mov rsi, rax
|           0x000007d9      488d3df50000.  lea rdi, qword [0x000008d5] ; "%d"
|           0x000007e0      b800000000     mov eax, 0
|           0x000007e5      e896feffff     call sym.imp.__isoc99_scanf
|           0x000007ea      8b45f4         mov eax, dword [local_ch]
|           0x000007ed      85c0           test eax, eax
|       ,=< 0x000007ef      7e0c           jle 0x7fd
|       |   0x000007f1      488d3de00000.  lea rdi, qword str.The_number_is_positive. ; 0x8d8 ; "The number is positive."
|       |   0x000007f8      e843feffff     call sym.imp.puts           ; int puts(const char *s)
|       |      ; JMP XREF from 0x000007ef (sym.func2)
|       `-> 0x000007fd      e86efeffff     call sym.imp.getchar        ; int getchar(void)
|           0x00000802      90             nop
|           0x00000803      488b55f8       mov rdx, qword [local_8h]
|           0x00000807      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x00000810      7405           je 0x817
|       |   0x00000812      e839feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       |      ; JMP XREF from 0x00000810 (sym.func2)
|       `-> 0x00000817      c9             leave
\           0x00000818      c3             ret
[0x000007aa]> 
```
Let's go step by step here. 
```
|           0x000007ae      4883ec10       sub rsp, 0x10
|           0x000007b2      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x1a08 ; '('
|           0x000007bb      488945f8       mov qword [local_8h], rax
|           0x000007bf      31c0           xor eax, eax

```
As we are playing on advantage here, we already know that the first thing done by the program at this point is declaring the number variable that will be used for storing the user input. The first two lines here may seem a bit confusing and in my opinion do not relate so much to the actual "algorithm" we are trying to analize, the first line is present in many fors in a lot of function calls and basically it allocates spaces in the stack for operating there, with variables and data structures, as we are using variables here, the program "reserves" some space, for sure we'll dig deeper on that later on, by know its ok for you to know it this way.
  
Then we find this weird mov rax, qword instruction that goes a bit beyond the scope of this post. It is inserted there by our gcc compiler and what it does is to set up a stack guard check against potential buffer overflow vulnerabilities. If we look closer to the code we can see a XOR operation within the same location at the end of the routine, in general terms, brieffly exaplained the program will check if the stak has been corrupted, if yes it will launch the __stack_chk_fail to safely deal with the problem. The whole thing is fantastically explained here https://stackoverflow.com/questions/10325713/why-does-this-memory-address-fs0x28-fs0x28-have-a-random-value The variable tagged as local_8h will be used to store that "canary"


Let's move on

```
|           0x000007c1      488d3dfc0000.  lea rdi, qword str.Enter_a_number: ; 0x8c4 ; "Enter a number: "
|           0x000007c8      b800000000     mov eax, 0
|           0x000007cd      e88efeffff     call sym.imp.printf         ; int printf(const char *format)
|           0x000007d2      488d45f4       lea rax, qword [local_ch]
|           0x000007d6      4889c6         mov rsi, rax
|           0x000007d9      488d3df50000.  lea rdi, qword [0x000008d5] ; "%d"
|           0x000007e0      b800000000     mov eax, 0
|           0x000007e5      e896feffff     call sym.imp.__isoc99_scanf

```
As we already know, on x64 systems, parameters or arguments are passed to the functions via the registers, so with lea rdi, "enter a number" we load the effective address of where the "Enter a number:" string is stored on memory to the register. We are not passing the whole string to the function, instead we are passing a reference to its location to the function, that concept is prettty important because if the function somehow modifies the string, its original value will get modified as well, if we pass a compy of the string rather than a reference any operations made inside the function with the copy won't affect the original.

So we see the string to be printed being passed by reference as a parameter to the printf function and then we see the eax register being zeroed. In the x86_64 ABI, if a function (such as printf) has variable arguments then AL (which is part of EAX) is expected to hold the number of vector registers (SSE, AVX) used to hold arguments to that function, in our case that number is zero. More info on those can be seen here https://www.codingame.com/playgrounds/283/sse-avx-vectorization/what-is-sse-and-avx 

So after those params being passed, the printf function gets called, that call should prompt the string to the stdout (screen).

Right after the call, we see a reference to the local_ch tag being loaded first into rax then into rsi. local_ch references an allocated space, commonly a variable, in this case it represents the variable "number". After that we see "%d" being loaded as a parameter as well, in this case into rdi, then eax gets zeroed and the program calls the scanf function. 

In common terms that block of code means printf("Enter a number:) and then scanf(%d, &number)

The next stage of the program is related to the value check for the user input.

```
|           0x000007e5      e896feffff     call sym.imp.__isoc99_scanf
|           0x000007ea      8b45f4         mov eax, dword [local_ch]
|           0x000007ed      85c0           test eax, eax
|       ,=< 0x000007ef      7e0c           jle 0x7fd
|       |   0x000007f1      488d3de00000.  lea rdi, qword str.The_number_is_positive. ; 0x8d8 ; "The number is positive."
|       |   0x000007f8      e843feffff     call sym.imp.puts           ; int puts(const char *s)
|       |      ; JMP XREF from 0x000007ef (sym.func2)
|       `-> 0x000007fd      e86efeffff     call sym.imp.getchar        ; int getchar(void)

```
After scanf, the user input (local_ch) gets moved to eax then as we saw on the previous a comparision with 0 is done with test and jle. If the user input is >0 the execution will continue to print "The number is positive" if that condition is not met the program goes straight to the end of the block.
  

After this point we can say that our simple analysis is over, let's proceed with an extra step.
  

Let's try now with an extra step, we'll add an else condition to see how the compiler deals with that.
```
#include <stdio.h>

func2(){
int num;
printf("Enter a number: ");
scanf("%d", &num);

if(num>0) printf("The number is positive.\n");
else printf("The number is negative.\n");
getchar();
}

main(){

func2();
getchar();

}
```

We can jump straight to the point now

```
|           0x000007e5      e896feffff     call sym.imp.__isoc99_scanf
|           0x000007ea      8b45f4         mov eax, dword [local_ch]
|           0x000007ed      85c0           test eax, eax
|       ,=< 0x000007ef      7e0e           jle 0x7ff
|       |   0x000007f1      488d3df00000.  lea rdi, qword str.The_number_is_positive. ; 0x8e8 ; "The number is positive."
|       |   0x000007f8      e843feffff     call sym.imp.puts           ; int puts(const char *s)
|      ,==< 0x000007fd      eb0c           jmp 0x80b
|      ||      ; JMP XREF from 0x000007ef (sym.func2)
|      |`-> 0x000007ff      488d3dfa0000.  lea rdi, qword str.The_number_is_negative. ; 0x900 ; "The number is negative."
|      |    0x00000806      e835feffff     call sym.imp.puts           ; int puts(const char *s)
|      |       ; JMP XREF from 0x000007fd (sym.func2)
|      `--> 0x0000080b      e860feffff     call sym.imp.getchar        ; int getchar(void)
```
As we can see, on this case if the number is not positive, we'll assume that is negative and we'll print the corresponding message instead of going straight to the getchar, for the rest of the program, everything works the same.

```
                                                   | test eax, eax                              |                                                   
                                                   | jle 0x7ff;[gc]                             |                                                   
                                                   `--------------------------------------------'                                                   
                                                           | |                                                                                      
                                                           | '--------------------.                                                                 
                              .----------------------------'                      |                                                                 
                              |                                                   |                                                                 
                              |                                                   |                                                                 
                      .------------------------------------------------.    .------------------------------------------------.                      
                      |  0x7f1 ;[gg]                                   |    |  0x7ff ;[gc]                                   |                      
                      |   ; 0x8e8                                      |    |      ; JMP XREF from 0x000007ef (sym.func2)    |                      
                      |   ; "The number is positive."                  |    |   ; 0x900                                      |                      
                      | lea rdi, qword str.The_number_is_positive.     |    |   ; "The number is negative."                  |                      
                      | call sym.imp.puts;[ge]                         |    | lea rdi, qword str.The_number_is_negative.     |                      
                      | jmp 0x80b;[gf]                                 |    | call sym.imp.puts;[ge]                         |                      
                      `------------------------------------------------'    `------------------------------------------------'                      
                          |                                                     |                                                                   
                          '----------------------------.                        |                                                                   
                                                       .------------------------'                                                                   
                                                       |                                                                                            
                                                       |                                                                                            
                                                   .---------------------------------------------.                          
```




```
#include <stdio.h>

func2(){
printf("Enter a key and then press enter: ");
char key;
scanf("%c",&key);

switch(key){
case ' ':
        printf("Space. \n");
        break;
case '1':
case '2':
case '3':
case '4':
case '5':
case '6':
case '7':
case '8':
case '9':
case '0': printf("Digit.\n");
break;
default: printf("Neither space nor digit.\n");
}

}

main(){
func2();
getchar();
}
```


```
#include <stdio.h>

func2(){
printf("Enter a key and then press enter: ");
int val;

printf("Select a fruit: \n");
printf("1: Apple\n");
printf("2: Orange\n");
printf("3: Banana\n");
printf("4: Pear\n");

scanf("%d",&val);

switch(val){
case 1:
        printf("Apple. \n");
        break;
case 2:
        printf("Orange. \n");
        break;
case 3:
        printf("Banana. \n");
        break;
case 4:
        printf("Pear. \n");
        break;

default: printf("Nothing selected.\n");
}

}

main(){
func2();
getchar();
}
```



```
#include <stdio.h>

func2(){
int num;

printf("Enter a num, (exit with 0):");

scanf("%d", &num);

while(num != 0){

        if(num > 0) printf("Positive num\n");
        else printf("Negative num\n");

        printf("Enter another num (exit with 0):");

        scanf("%d", &num);

}

}

main(){

func2();
getchar();

}
```



```
#include <stdio.h>


func2(){

int counter = 0;

for(counter=1; counter <=10; counter++){

        printf("%d ", counter);

}

}


main(){

        func2();
        getchar();

}


```
