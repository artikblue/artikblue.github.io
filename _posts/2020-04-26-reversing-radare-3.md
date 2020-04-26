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

Inside radare2 there's a cleaner way to inspect code bifurcations such as the one we've just seen. If you type VV inside a function you'll be able to inspect it visually.

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



#### SWITCH CASE
The switch case cames with a more advanced scenario than if else. The if else statement works fine if we have a couple or three ways we plan to redirect the execution flow of the program but if we have a lot of diferent cases we may want to use something more advanced such as switch case.

We will work with the following piece of code
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
As we can see, the code is pretty simple, as usual all the magic happens within the func2 function. Here the program reads a character from the standard input and passes it to the switch function. Then, the value of the character will be evaluated through all of the case's. If the character entered is a space a print will be called and then the check will end with the break instruction, that means on that case the program will jump straight out of the switch block.  

Those next case statements can be interpreted as a very long if sentence each case being something like if key == 'X' followed by an and (&&) and then the next condtion. That translates to the following: if the input goes from '0' to '9' then it means that the user has entered a digit and "Digit.\n" will be printed  break will be executed and the program flow will be directed outside of the switch block. If no case condition is met, the program will execute whats in the default case, "Neither space nor digit".

Now that we know what this program does let's go straight to radare2. This time we will analyze the bin both statically and dynamically

```
red@blue:~/c/chapter3$ radare2 -d case
Process with PID 7901 started...
= attach 7901 7901
bin.baddr 0x560c23c18000
Using 0x560c23c18000
asm.bits 64
[0x7ff6a3b32090]> aaa
[ WARNING : block size exceeding max block size at 0x560c23e18fe0
[+] Try changing it with e anal.bb.maxsize
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
= attach 7901 7901
7901
[0x7ff6a3b32090]> 
```
As we see, we started the program with the -d flag so we can debug it. What we want to analyze is inside the func2 function, so we can start by looking there.

```
[0x7ff6a3b32090]> s sym.func2
[0x560c23c187aa]> pdf
/ (fcn) sym.func2 154
|   sym.func2 ();
|           ; var int local_9h @ rbp-0x9
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x560c23c1884d (sym.main)
|           0x560c23c187aa      55             push rbp
|           0x560c23c187ab      4889e5         mov rbp, rsp
|           0x560c23c187ae      4883ec10       sub rsp, 0x10
|           0x560c23c187b2      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x560c23c187bb      488945f8       mov qword [local_8h], rax
|           0x560c23c187bf      31c0           xor eax, eax
|           0x560c23c187c1      488d3d200100.  lea rdi, qword str.Enter_a_key_and_then_press_enter: ; 0x560c23c188e8 ; "Enter a key and then press enter: "
|           0x560c23c187c8      b800000000     mov eax, 0
|           0x560c23c187cd      e88efeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x560c23c187d2      488d45f7       lea rax, qword [local_9h]
|           0x560c23c187d6      4889c6         mov rsi, rax
|           0x560c23c187d9      488d3d2b0100.  lea rdi, qword [0x560c23c1890b] ; "%c"
|           0x560c23c187e0      b800000000     mov eax, 0
|           0x560c23c187e5      e896feffff     call sym.imp.__isoc99_scanf
|           0x560c23c187ea      0fb645f7       movzx eax, byte [local_9h]
|           0x560c23c187ee      0fbec0         movsx eax, al
|           0x560c23c187f1      83f820         cmp eax, 0x20           ; 32
|       ,=< 0x560c23c187f4      740f           je 0x560c23c18805
|       |   0x560c23c187f6      83f820         cmp eax, 0x20           ; 32
|      ,==< 0x560c23c187f9      7c26           jl 0x560c23c18821
|      ||   0x560c23c187fb      83e830         sub eax, 0x30           ; '0'
|      ||   0x560c23c187fe      83f809         cmp eax, 9              ; 9
|     ,===< 0x560c23c18801      771e           ja 0x560c23c18821
|    ,====< 0x560c23c18803      eb0e           jmp 0x560c23c18813
|    |||`-> 0x560c23c18805      488d3d020100.  lea rdi, qword str.Space. ; 0x560c23c1890e ; "Space. "
|    |||    0x560c23c1880c      e82ffeffff     call sym.imp.puts       ; int puts(const char *s)
|    |||,=< 0x560c23c18811      eb1a           jmp 0x560c23c1882d
|    ||||      ; JMP XREF from 0x560c23c18803 (sym.func2)
|    `----> 0x560c23c18813      488d3dfc0000.  lea rdi, qword str.Digit. ; 0x560c23c18916 ; "Digit."
|     |||   0x560c23c1881a      e821feffff     call sym.imp.puts       ; int puts(const char *s)
|    ,====< 0x560c23c1881f      eb0c           jmp 0x560c23c1882d
|    |``--> 0x560c23c18821      488d3df50000.  lea rdi, qword str.Neither_space_nor_digit. ; 0x560c23c1891d ; "Neither space nor digit."
|    |  |   0x560c23c18828      e813feffff     call sym.imp.puts       ; int puts(const char *s)
|    |  |      ; JMP XREF from 0x560c23c18811 (sym.func2)
|    |  |      ; JMP XREF from 0x560c23c1881f (sym.func2)
|    `--`-> 0x560c23c1882d      90             nop
|           0x560c23c1882e      488b55f8       mov rdx, qword [local_8h]
|           0x560c23c18832      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x560c23c1883b      7405           je 0x560c23c18842
|       |   0x560c23c1883d      e80efeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x560c23c18842      c9             leave
\           0x560c23c18843      c3             ret
[0x560c23c187aa]> 
```
As we arelady say, this block starts with the stack protecion mechanism we early presented. As we can see the control of the execution flow here is a bit more complex. That is a thing that will happen to you sometimes as you are engaged in ctfs or even real reverse engineering projects. There are two common solutions to be applied on these situations. We can either jump to the visual mode or inspect for strings or interesting function calls. Here we can easily detect the strings Space, Digit and Neither space or digit, that says a lot and basically solves the problem, as we easily identify three main cases. 


The magic here starts with the scanf
```
|           0x560c23c187d2      488d45f7       lea rax, qword [local_9h]
|           0x560c23c187d6      4889c6         mov rsi, rax
|           0x560c23c187d9      488d3d2b0100.  lea rdi, qword [0x560c23c1890b] ; "%c"
|           0x560c23c187e0      b800000000     mov eax, 0
|           0x560c23c187e5      e896feffff     call sym.imp.__isoc99_scanf
|           0x560c23c187ea      0fb645f7       movzx eax, byte [local_9h]
|           0x560c23c187ee      0fbec0         movsx eax, al
|           0x560c23c187f1      83f820         cmp eax, 0x20           ; 32
|       ,=< 0x560c23c187f4      740f           je 0x560c23c18805

```
On this example, we start by passing a couple of params to scanf function via the registers, with %c we indicate that we are going to read a character and local_9h will be the location of that character in memory.

After reading the char value from the user input, the program gets it ready to be compared against the character set on the first case statement. As a char in C is stored in one (1) byte, the program only needs the content of AL (RAX/EAX lower). After loading the "corrected" value, the progrram compares it with 0x20 that represents the value for 'space' according to the ascii table. 
  

```
|           0x560c23c187f1      83f820         cmp eax, 0x20           ; 32
|       ,=< 0x560c23c187f4      740f           je 0x560c23c18805
|       |   0x560c23c187f6      83f820         cmp eax, 0x20           ; 32
|      ,==< 0x560c23c187f9      7c26           jl 0x560c23c18821
|      ||   0x560c23c187fb      83e830         sub eax, 0x30           ; '0'
|      ||   0x560c23c187fe      83f809         cmp eax, 9              ; 9
|     ,===< 0x560c23c18801      771e           ja 0x560c23c18821
|    ,====< 0x560c23c18803      eb0e           jmp 0x560c23c18813
|    |||`-> 0x560c23c18805      488d3d020100.  lea rdi, qword str.Space. ; 0x560c23c1890e ; "Space. "
|    |||    0x560c23c1880c      e82ffeffff     call sym.imp.puts       ; int puts(const char *s)
|    |||,=< 0x560c23c18811      eb1a           jmp 0x560c23c1882d
|    ||||      ; JMP XREF from 0x560c23c18803 (sym.func2)
|    `----> 0x560c23c18813      488d3dfc0000.  lea rdi, qword str.Digit. ; 0x560c23c18916 ; "Digit."
|     |||   0x560c23c1881a      e821feffff     call sym.imp.puts       ; int puts(const char *s)
|    ,====< 0x560c23c1881f      eb0c           jmp 0x560c23c1882d
|    |``--> 0x560c23c18821      488d3df50000.  lea rdi, qword str.Neither_space_nor_digit. ; 0x560c23c1891d ; "Neither space nor digit."
|    |  |   0x560c23c18828      e813feffff     call sym.imp.puts       ; int puts(const char *s)
|    |  |      ; JMP XREF from 0x560c23c18811 (sym.func2)
|    |  |      ; JMP XREF from 0x560c23c1881f (sym.func2)
|    `--`-> 0x560c23c1882d      90             nop
```
As you can see if the content of eax (the input) is equal to the value of space the program will jump to 0x560c23c18805 and there it will prompt "space", after prompting that it will exit out of the block by jumping directly to 0x560c23c1882d (nop).


What's interesting here comes right after. After this first comparision, if the jump condition is not met, the program will compare again the value with a space this time checking if the value is LESS THAN a space, if its less than a space the program will jump to the "Neither space nor digit" and exit the block, why that? That's an easy trick for the compilers to check if some character is outside a range of characters. As you yourself can check, all of the digits between 0 and 9 have values higher than 0x20 on the ascii table, so anything below 0x20 must not be a digit.

Then the last comparision is done here:

```
|      ||   0x560c23c187fb      83e830         sub eax, 0x30           ; '0'
|      ||   0x560c23c187fe      83f809         cmp eax, 9              ; 9
|     ,===< 0x560c23c18801      771e           ja 0x560c23c18821
|    ,====< 0x560c23c18803      eb0e           jmp 0x560c23c18813
```
The program substracts 0x30 from eax and the compares it to 0x9 why tho? Well, thats another computationally easy way for the compiler to do that, the ascii value from char '9' is 0x39 so that minus 0x30 returns 0x9. After the comparision ja is executed to jump to the "Digit" printf if the condition (key = '9') is met, other wise the program goes to the "neither space or digit" zone and exits.
  
Let's examine this more in depth by actually debuging the program entering a digit.

we start by setting a couple of breakpoints here and there


```
[0x560c23c187aa]> db 0x560c23c187f1
[0x560c23c187aa]> db 0x560c23c187fb
[0x560c23c187aa]> 
```

Then we launch the execution to the first breakpoint

```
[0x560c23c187aa]> dc
Enter a key and then press enter: 5
hit breakpoint at: 560c23c187f1
[0x560c23c187f1]> pdb
/ (fcn) sym.func2 154
|   sym.func2 ();
|           ; var int local_9h @ rbp-0x9
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x560c23c1884d (sym.main)
|           0x560c23c187aa      55             push rbp
|           0x560c23c187ab      4889e5         mov rbp, rsp
|           0x560c23c187ae      4883ec10       sub rsp, 0x10
|           0x560c23c187b2      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x560c23c187bb      488945f8       mov qword [local_8h], rax
|           0x560c23c187bf      31c0           xor eax, eax
|           0x560c23c187c1      488d3d200100.  lea rdi, qword str.Enter_a_key_and_then_press_enter: ; 0x560c23c188e8 ; "Enter a key and then press enter: "
|           0x560c23c187c8      b800000000     mov eax, 0
|           0x560c23c187cd      e88efeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x560c23c187d2      488d45f7       lea rax, qword [local_9h]
|           0x560c23c187d6      4889c6         mov rsi, rax
|           0x560c23c187d9      488d3d2b0100.  lea rdi, qword [0x560c23c1890b] ; "%c"
|           0x560c23c187e0      b800000000     mov eax, 0z
|           0x560c23c187e5      e896feffff     call sym.imp.__isoc99_scanf
|           0x560c23c187ea      0fb645f7       movzx eax, byte [local_9h]
|           0x560c23c187ee      0fbec0         movsx eax, al
|           ;-- rip:
|           0x560c23c187f1 b    83f820         cmp eax, 0x20           ; 32
|       ,=< 0x560c23c187f4      740f           je 0x560c23c18805
[0x560c23c187f1]> 
```
So the '5' value has been loaded into the variable and thus now in AL (RAX)

```
|           0x560c23c187f1 b    83f820         cmp eax, 0x20           ; 32
|       ,=< 0x560c23c187f4      740f           je 0x560c23c18805
[0x560c23c187f1]> dr
rax = 0x00000035
```
So rax = 0x35 corresponding to '5' in ascii. '5' will get compared to ' ' and as they are not the same number, the zero flag will remain zero.
```
[0x560c23c187f1]> ds
[0x560c23c187f1]> dr 1
cf = 0x00000000
pf = 0x00000000
af = 0x00000000
zf = 0x00000000
sf = 0x00000000
tf = 0x00000000
if = 0x00000001
df = 0x00000000
of = 0x00000000
[0x560c23c187f1]> 
```
After that the execution flow will go on and we'll met the other cmp. 

Cmp works like this with flags

```
Assume result = op1 - op2

CF - 1 if unsigned op2 > unsigned op1
OF - 1 if sign bit of OP1 != sign bit of result
SF - 1 if MSB (aka sign bit) of result = 1
ZF - 1 if Result = 0 (i.e. op1=op2)
AF - 1 if Carry in the low nibble of result
PF - 1 if Parity of Least significant byte is even
```

As none of this is met, flags will remain zero. After that 0x30 will be substracted from our value, so 0x35 - 0x30 = 0x5. 



```
      ||   0x560c23c187fb b    83e830         sub eax, 0x30           ; '0'
|      ||   0x560c23c187fe      83f809         cmp eax, 9              ; 9
|     ,===< 0x560c23c18801      771e           ja 0x560c23c18821
|     |||   ;-- rip:
|    ,====< 0x560c23c18803      eb0e           jmp 0x560c23c18813
|    |||`-> 0x560c23c18805      488d3d020100.  lea rdi, qword str.Space. ; 0x560c23c1890e ; "Space. "
```
Then the value will be compared to 9 so the flags will look like those 


```
[0x560c23c187f1]> dr 1
cf = 0x00000001
pf = 0x00000001
af = 0x00000001
zf = 0x00000000
sf = 0x00000001
tf = 0x00000000
if = 0x00000001
df = 0x00000000
of = 0x00000000
[0x560c23c187f1]> 
```
And as ja = Jump short if above (CF=0 and ZF=0) the execution flow will jump right to the "Digit" printf.

```
|    ||||      ; JMP XREF from 0x560c23c18803 (sym.func2)
|    `----> 0x560c23c18813      488d3dfc0000.  lea rdi, qword str.Digit. ; 0x560c23c18916 ; "Digit."
|     |||   0x560c23c1881a      e821feffff     call sym.imp.puts       ; int puts(const char *s)
|    ,====< 0x560c23c1881f      eb0c           jmp 0x560c23c1882d
```
At this point we already know how the program is going to end so let's move to our last switch-case example.



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
                                                                                                       | cmp eax, 2                                               |                                               
                                                                                                        | je 0x854;[gd]                                            |                                               
                                                                                                        `----------------------------------------------------------'                                               
                                                                                                                | |                                                                                                
                                                                                                                | '--------------------------------------------.                                                   
                                                                                         .----------------------'                                              |                                                   
                                                                                         |                                                                     |                                                   
                                                                                         |                                                                     |                                                   
                                                                                 .--------------------.                                                  .---------------------------------------------.           
                                                                                 |  0x82e ;[gg]       |                                                  |  0x854 ;[gd]                                |           
                                                                                 | cmp eax, 2         |                                                  |      ; JMP XREF from 0x0000082c (sym.func2) |           
                                                                                 | jg 0x83a;[gf]      |                                                  |   ; 0x9ac                                   |           
                                                                                 `--------------------'                                                  |   ; "Orange. "                              |           
                                                                                         | |                                                             | lea rdi, qword str.Orange.                  |           
                                                                                         | |                                                             | call sym.imp.puts;[gb]                      |           
                                                                                         | |                                                             | jmp 0x88a;[gp]                              |           
                                                                                         | |                                                             `---------------------------------------------'           
                                                                                         | |                                                                 |                                                     
                                                                                         | '---------------------.                                           |                                                     
                                                   .-------------------------------------'                       |                                           |                                                     
                                                   |                                                             |                                           '------------------.                                  
                                                   |                                                             |                                                              |                                  
                                                   |                                                             |                                                              |                                  
                                           .--------------------.                                          .---------------------------------------------.                      |                                  
                                           |  0x833 ;[gi]       |                                          |  0x83a ;[gf]                                |                      |                                  
                                           | cmp eax, 1         |                                          |      ; JMP XREF from 0x00000831 (sym.func2) |                      |                                  
                                           | je 0x846;[gh]      |                                          | cmp eax, 3                                  |                      |                                  
                                           `--------------------'                                          | je 0x862;[gl]                               |                      |                                  
                                                   | |                                                     `---------------------------------------------'                      |                                  
                                                   | |                                                             | |                                                          |                                  
                                                   | '--.                                                          | |                                                          |                                  
                                .------------------'    |                                                          | |                                                          |                                  
                                |                       |                                                          | '--------------.                                           |                                  
                                |                       |                                                   .------'                |                                           |                                  
                                |                       |                                                   |                       |                                           |                                  
                                |                       |                                                   |                       |                                           |                                  
                        .--------------------.    .---------------------------------------------.   .--------------------.    .---------------------------------------------.   |                                  
                        |  0x838 ;[gk]       |    |  0x846 ;[gh]                                |   |  0x83f ;[gn]       |    |  0x862 ;[gl]                                |   |                                  
                        | jmp 0x87e;[gj]     |    |      ; JMP XREF from 0x00000836 (sym.func2) |   | cmp eax, 4         |    |      ; JMP XREF from 0x0000083d (sym.func2) |   |                                  
                        `--------------------'    |   ; 0x9a4                                   |   | je 0x870;[gm]      |    |   ; 0x9b5                                   |   |                                  
                            |                     |   ; "Apple. "                               |   `--------------------'    |   ; "Banana. "                              |   |                                  
                            |                     | lea rdi, qword str.Apple.                   |           | |               | lea rdi, qword str.Banana.                  |   |                                  
                            |                     | call sym.imp.puts;[gb]                      |           | |               | call sym.imp.puts;[gb]                      |   |                                  
                            |                     | jmp 0x88a;[gp]                              |           | |               | jmp 0x88a;[gp]                              |   |                                  
                            |                     `---------------------------------------------'           | |               `---------------------------------------------'   | 
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
