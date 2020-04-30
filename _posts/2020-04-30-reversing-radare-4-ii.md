---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 4 - II (more strings)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare_5.png
featured_image: assets/images/radare2/radare_5.png
---

On this one, we are going to walk a little bit more through char arrays and strings to set solid fundamentals on the topic so we can move on and study more complex data structures (such as multi-dimensional arrays and structs).



#### A refresher on char arrays

As we seen on the previous post, strings can be declared as charr arrays of a fixed size, then they can be printed out by printf using %s for the format.
```
# include <stdio.h>

main(){
 func();
 getchar();
 getchar();
 getchar();    
}

func(){

    char text[40];
    printf("Name?: ");
    scanf("%s", &text);
    printf("Hi, %s\n", text);

}
```
But an interesting thing to note from scanf here is that scanf will read anything that comes before a space, let's check it out:

```
[0x5653b864f78e]> pdf
/ (fcn) sym.func 111
|   sym.func ();
|           ; var int local_30h @ rbp-0x30
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x5653b864f773 (sym.main)
|           0x5653b864f78e      55             push rbp
|           0x5653b864f78f      4889e5         mov rbp, rsp
|           0x5653b864f792      4883ec30       sub rsp, 0x30           ; '0'
|           0x5653b864f796      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x5653b864f79f      488945f8       mov qword [local_8h], rax
|           0x5653b864f7a3      31c0           xor eax, eax
|           0x5653b864f7a5      488d3dd80000.  lea rdi, qword str.Name_: ; 0x5653b864f884 ; "Name?: "
|           0x5653b864f7ac      b800000000     mov eax, 0
|           0x5653b864f7b1      e86afeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5653b864f7b6      488d45d0       lea rax, qword [local_30h]
|           0x5653b864f7ba      4889c6         mov rsi, rax
|           0x5653b864f7bd      488d3dc80000.  lea rdi, qword [0x5653b864f88c] ; "%s"
|           0x5653b864f7c4      b800000000     mov eax, 0
|           0x5653b864f7c9      e872feffff     call sym.imp.__isoc99_scanf
|           0x5653b864f7ce      488d45d0       lea rax, qword [local_30h]
|           0x5653b864f7d2      4889c6         mov rsi, rax
|           0x5653b864f7d5      488d3db30000.  lea rdi, qword str.Hi___s ; 0x5653b864f88f ; "Hi, %s\n"
|           0x5653b864f7dc      b800000000     mov eax, 0
|           0x5653b864f7e1      e83afeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5653b864f7e6      90             nop
|           0x5653b864f7e7      488b55f8       mov rdx, qword [local_8h]
|           0x5653b864f7eb      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x5653b864f7f4      7405           je 0x5653b864f7fb
|       |   0x5653b864f7f6      e815feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x5653b864f7fb      c9             leave
\           0x5653b864f7fc      c3             ret
[0x5653b864f78e]> db 0x5653b864f7dc
[0x7f1e4dda4090]> dc
Name?: sample text
hit breakpoint at: 5653b864f7dc
[0x5653b864f7dc]> 
``` 
After setting a breakpoint right after the printf and running the program, we'll be asked for an input, we can input something such as "sample text" and common sense tells us that the output after running printf should be "Hi, sample text" but nope
```
|           0x5653b864f7c9      e872feffff     call sym.imp.__isoc99_scanf
|           0x5653b864f7ce      488d45d0       lea rax, qword [local_30h]
|           0x5653b864f7d2      4889c6         mov rsi, rax
|           0x5653b864f7d5      488d3db30000.  lea rdi, qword str.Hi___s ; 0x5653b864f88f ; "Hi, %s\n"
|           ;-- rip:
|           0x5653b864f7dc b    b800000000     mov eax, 0
|           0x5653b864f7e1      e83afeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5653b864f7e6      90             nop
|           0x5653b864f7e7      488b55f8       mov rdx, qword [local_8h]
|           0x5653b864f7eb      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x5653b864f7f4      7405           je 0x5653b864f7fb
|       |   0x5653b864f7f6      e815feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x5653b864f7fb      c9             leave
\           0x5653b864f7fc      c3             ret
[0x5653b864f7dc]> dr
rax = 0x7ffceeaaabd0
rbx = 0x00000000
rcx = 0x7f1e4dd9e560
rdx = 0x7f1e4dd9f8d0
r8 = 0x00000000
r9 = 0x00000000
r10 = 0x00000000
r11 = 0x5653b864f88e
r12 = 0x5653b864f660
r13 = 0x7ffceeaaacf0
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x7ffceeaaabd0
rdi = 0x5653b864f88f
rsp = 0x7ffceeaaabd0
rbp = 0x7ffceeaaac00
rip = 0x5653b864f7dc
rflags = 0x00000206
orax = 0xffffffffffffffff
[0x5653b864f7dc]> pxw @ 0x7ffceeaaabd0
0x7ffceeaaabd0  0x706d6173 0x0000656c 0xb864f84d 0x00005653  sample..M.d.SV..
```
As we can see, scanf only stored "sample" ommiting " text". That is because scanf means scan formated, so we need to specify the input we are expecting, we need to define a format specifier (https://codeforwin.org/2015/05/list-of-all-format-specifiers-in-c-programming.html). Calling the function in a way such as this one:
```
scanf("%[^\n]",text);
```
Will allow spaces to be registered. Consider the following link https://www.includehelp.com/c/c-program-to-read-string-with-spaces-using-scanf-function.aspx if you want to go deeper on the topic. For now its ok to know that scanf reads from input based on a specifier, the same way printf outputs content.

#### Puts and gets
Other methods for receiving strings from the input or printing them out are gets and puts. Gets eeads characters from the standard input and stores them as a string and prints characters from the standard output. Both act in a similar way as printf and scanf, the main difference here is that there is no specification on the format. The main difference here comes from the format (https://www.geeksforgeeks.org/difference-between-scanf-and-gets-in-c/) as, for example, by default gets won't stop if it encounters a whitespace. Same thing with puts, puts will just dump the contents of the char array interpreting it as a string.

Let's inspect the following code:
```
# include <stdio.h>

main(){
 func();
 getchar();

}

func(){

    char text[40];
    puts("Name?: ");
    gets(text);
    printf("Ho, %s\n", text);
}
```
Here puts is used the same way as printf and gets is used for reading from stdin, let's see:
```
[0x5618704127a4]> pdf
/ (fcn) sym.func 99
|   sym.func ();
|           ; var int local_30h @ rbp-0x30
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x561870412793 (sym.main)
|           0x5618704127a4      55             push rbp
|           0x5618704127a5      4889e5         mov rbp, rsp
|           0x5618704127a8      4883ec30       sub rsp, 0x30           ; '0'
|           0x5618704127ac      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x5618704127b5      488945f8       mov qword [local_8h], rax
|           0x5618704127b9      31c0           xor eax, eax
|           0x5618704127bb      488d3dd20000.  lea rdi, qword str.Name_: ; 0x561870412894 ; "Name?: "
|           0x5618704127c2      e859feffff     call sym.imp.puts       ; int puts(const char *s)
|           0x5618704127c7      488d45d0       lea rax, qword [local_30h]
|           0x5618704127cb      4889c7         mov rdi, rax
|           0x5618704127ce      b800000000     mov eax, 0
|           0x5618704127d3      e888feffff     call sym.imp.gets       ; char*gets(char *s)
|           0x5618704127d8      488d45d0       lea rax, qword [local_30h]
|           0x5618704127dc      4889c6         mov rsi, rax
|           0x5618704127df      488d3db60000.  lea rdi, qword str.Ho___s ; 0x56187041289c ; "Ho, %s\n"
|           0x5618704127e6      b800000000     mov eax, 0
|           0x5618704127eb      e850feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5618704127f0      90             nop
|           0x5618704127f1      488b55f8       mov rdx, qword [local_8h]
|           0x5618704127f5      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x5618704127fe      7405           je 0x561870412805
|       |   0x561870412800      e82bfeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x561870412805      c9             leave
\           0x561870412806      c3             ret
[0x5618704127a4]> 
```
Again in this case, the string "Name..." is passed to the puts function by using rdi, we also see that eax is zeroed probably because of no vector registers are in use. Then we have the gets function:
```
|           0x5618704127c7      488d45d0       lea rax, qword [local_30h]
|           0x5618704127cb      4889c7         mov rdi, rax
|           0x5618704127ce      b800000000     mov eax, 0
|           0x5618704127d3      e888feffff     call sym.imp.gets       ; char*gets(char *s)
```
Again, local_30h is used as a pointer to the string to be read and it is passed to the gets function by the rdi register.

If we debug the function, this time we should be able to see how the full string is stored, including white spaces.
```
|           0x5618704127d3      e888feffff     call sym.imp.gets       ; char*gets(char *s)
|           0x5618704127d8      488d45d0       lea rax, qword [local_30h]
|           0x5618704127dc      4889c6         mov rsi, rax
|           0x5618704127df      488d3db60000.  lea rdi, qword str.Ho___s ; 0x56187041289c ; "Ho, %s\n"
|           0x5618704127e6      b800000000     mov eax, 0
|           0x5618704127eb      e850feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5618704127f0      90             nop
|           0x5618704127f1      488b55f8       mov rdx, qword [local_8h]
|           0x5618704127f5      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x5618704127fe      7405           je 0x561870412805
|       |   0x561870412800      e82bfeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x561870412805      c9             leave
\           0x561870412806      c3             ret
[0x5618704127a4]> db 0x5618704127df
[0x5618704127a4]> dc
Name?: 
SAMPLE TEXT
hit breakpoint at: 5618704127df
[0x5618704127a4]> dr
rax = 0x7ffe03c95df0
rbx = 0x00000000
rcx = 0x7f9f10693a00
rdx = 0x7f9f106958d0
r8 = 0x561870acd67c
r9 = 0x7f9f108a34c0
r10 = 0x561870acd010
r11 = 0x00000246
r12 = 0x561870412680
r13 = 0x7ffe03c95f10
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x7ffe03c95df0
rdi = 0x7ffe03c95df1
rsp = 0x7ffe03c95df0
rbp = 0x7ffe03c95e20
rip = 0x5618704127df
rflags = 0x00000246
orax = 0xffffffffffffffff
[0x5618704127a4]> pxw @ 0x7ffe03c95df0
0x7ffe03c95df0  0x504d4153 0x5420454c 0x00545845 0x00005618  SAMPLE TEXT..V..¡
```
Voilà! As we have seen the full string is stored in memory this time. It is important to remark that the usage of functions such as scanf and gets is not recommended at all if we are trying to build something serious, as the user input is not controlled at all. As we have seen, with gets, the user input is literally dumpted to memory, starting at a particular memory address related to the beginning of the char array so if the user enters a really large string of characters, something way larger than the array space it will probably break the program, also, as gets reads whatever the user dumps to stdin and stores it in memory, the user can even enter code that may be executed. 

#### Strlen
We can interact with char arrays in different ways. A function that you'll probably encounter in many programs and ctf games is the strlen, that returns the lenght of a string.
```

# include <stdio.h>

main(){
 func();
 getchar();

}

func(){

    char text[40];
    puts("Name?: ");
    gets(text);
    printf("Hi, %s\n", text);
    printf("Length: %d chars", strlen(text));
}
```
strlen goes through the string and counts how many positions does hit have, it goes through the string char by char untill it encounters a null terminator (\0). We'll check what that means right now:

```
[0x55df8ad0a7e4]> pdf
/ (fcn) sym.func 131
|   sym.func ();
|           ; var int local_30h @ rbp-0x30
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x55df8ad0a7d3 (sym.main)
|           0x55df8ad0a7e4      55             push rbp
|           0x55df8ad0a7e5      4889e5         mov rbp, rsp
|           0x55df8ad0a7e8      4883ec30       sub rsp, 0x30           ; '0'
|           0x55df8ad0a7ec      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x55df8ad0a7f5      488945f8       mov qword [local_8h], rax
|           0x55df8ad0a7f9      31c0           xor eax, eax
|           0x55df8ad0a7fb      488d3df20000.  lea rdi, qword str.Name_: ; 0x55df8ad0a8f4 ; "Name?: "
|           0x55df8ad0a802      e849feffff     call sym.imp.puts       ; int puts(const char *s)
|           0x55df8ad0a807      488d45d0       lea rax, qword [local_30h]
|           0x55df8ad0a80b      4889c7         mov rdi, rax
|           0x55df8ad0a80e      b800000000     mov eax, 0
|           0x55df8ad0a813      e888feffff     call sym.imp.gets       ; char*gets(char *s)
|           0x55df8ad0a818      488d45d0       lea rax, qword [local_30h]
|           0x55df8ad0a81c      4889c6         mov rsi, rax
|           0x55df8ad0a81f      488d3dd60000.  lea rdi, qword str.Hi___s ; 0x55df8ad0a8fc ; "Hi, %s\n"
|           0x55df8ad0a826      b800000000     mov eax, 0
|           0x55df8ad0a82b      e850feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55df8ad0a830      488d45d0       lea rax, qword [local_30h]
|           0x55df8ad0a834      4889c7         mov rdi, rax
|           0x55df8ad0a837      e824feffff     call sym.imp.strlen     ; size_t strlen(const char *s)
|           0x55df8ad0a83c      4889c6         mov rsi, rax
|           0x55df8ad0a83f      488d3dbe0000.  lea rdi, qword str.Length:__d_chars ; 0x55df8ad0a904 ; "Length: %d chars"
|           0x55df8ad0a846      b800000000     mov eax, 0
|           0x55df8ad0a84b      e830feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55df8ad0a850      90             nop
|           0x55df8ad0a851      488b55f8       mov rdx, qword [local_8h]
|           0x55df8ad0a855      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x55df8ad0a85e      7405           je 0x55df8ad0a865
|       |   0x55df8ad0a860      e80bfeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x55df8ad0a865      c9             leave
\           0x55df8ad0a866      c3             ret
[0x55df8ad0a7e4]> 
```
Let's focus on the strlen function. 
```
|           0x55df8ad0a82b      e850feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55df8ad0a830      488d45d0       lea rax, qword [local_30h]
|           0x55df8ad0a834      4889c7         mov rdi, rax
|           0x55df8ad0a837      e824feffff     call sym.imp.strlen     ; size_t strlen(const char *s)
|           0x55df8ad0a83c      4889c6         mov rsi, rax
```
As usual, the string is located inside local_30h. So that reference is loaded inside rdi as a parameter and then strlen is called. Let's place some breakpoints and analyze the program.
```
[0x55df8ad0a7e4]> dc
Name?: 
SAMPLE TEXT
Hi, SAMPLE TEXT
hit breakpoint at: 55df8ad0a834

[0x55df8ad0a834]> dr
rax = 0x7ffcfc542170
[...]
[0x55df8ad0a834]> pxw @ 0x7ffcfc542170
0x7ffcfc542170  0x504d4153 0x5420454c 0x00545845 0x000055df  SAMPLE TEXT..U..
```
We can see how "SAMPLE TEXT" has been stored as string inside local_30h and if we pay a bit more attention to the memory dump, we can see that the string ends with a 0x00, that is a null terminator, so strlen will keep reading untill it reaches that null terminator.


If we go on and examine strlen, we'll see that the function returns its value (the lenght of string) using the RAX register.

```
[0x55df8ad0a834]> dc
hit breakpoint at: 55df8ad0a83c
[0x55df8ad0a834]> dr
rax = 0x0000000b
```
As we can see, rax contains 0xb = 11dec and "SAMPLE TEXT" has a lenght of 11 (space included)


#### The string library
The string library "string.h" contains various functions very useful for string manipulation. Those functions allow us to manipulate strings in many ways, in here we'll see how it is useful for copying strings.

Consider the following program:
```
# include <stdio.h>
# include <string.h>


main(){
 func();
 getchar();

}

func(){

    char text1[40], text2[40], text3[10];
 
    printf("Enter a string NOW: ");
    gets(text1);
 
    strcpy(text2, text1);
    printf("Copied string =  %s\n", text2);
    strncpy(text3, text1, 4);
    printf("4 first chars = %s\n", text3);

}

```
We see strings.h being included on top, then 3 char arrays are declared and strcpy is used to copy the contets of one to another.


We can easily detect the strings library being used with afl
```
:~/chapter5$ radare2 ./string
[0x000006d0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[0x000006d0]> afl
0x00000000    2 25           sym.imp.__libc_start_main
0x00000630    3 23           sym._init
0x00000660    1 6            sym.imp.strncpy
0x00000670    1 6            sym.imp.strcpy
0x00000680    1 6            sym.imp.__stack_chk_fail
0x00000690    1 6            sym.imp.printf
0x000006a0    1 6            sym.imp.getchar
0x000006b0    1 6            sym.imp.gets
0x000006c0    1 6            sub.__cxa_finalize_248_6c0
0x000006d0    1 43           entry0
0x00000700    4 50   -> 40   sym.deregister_tm_clones
0x00000740    4 66   -> 57   sym.register_tm_clones
0x00000790    4 49           sym.__do_global_dtors_aux
0x000007d0    1 10           entry1.init
0x000007da    1 26           sym.main
0x000007f4    3 171          sym.func
0x000008a0    4 101          sym.__libc_csu_init
0x00000910    1 2            sym.__libc_csu_fini
0x00000914    1 9            sym._fini
[0x000006d0]> 
```
And with ii/il
```
[0x7f47eeef5090]> il
[Linked libraries]
libc.so.6

1 library

[0x7f47eeef5090]> ii
[Imports]
   1 0x55896339b660  GLOBAL    FUNC strncpy
   2 0x55896339b000    WEAK  NOTYPE _ITM_deregisterTMCloneTable
   3 0x55896339b670  GLOBAL    FUNC strcpy
   4 0x55896339b680  GLOBAL    FUNC __stack_chk_fail
   5 0x55896339b690  GLOBAL    FUNC printf
   6 0x55896339b000  GLOBAL    FUNC __libc_start_main
   7 0x55896339b6a0  GLOBAL    FUNC getchar
   8 0x55896339b000    WEAK  NOTYPE __gmon_start__
   9 0x55896339b6b0  GLOBAL    FUNC gets
  10 0x55896339b000    WEAK  NOTYPE _ITM_registerTMCloneTable
  11 0x55896339b000    WEAK    FUNC __cxa_finalize
   2 0x55896339b000    WEAK  NOTYPE _ITM_deregisterTMCloneTable
   6 0x55896339b000  GLOBAL    FUNC __libc_start_main
   8 0x55896339b000    WEAK  NOTYPE __gmon_start__
  10 0x55896339b000    WEAK  NOTYPE _ITM_registerTMCloneTable
  11 0x55896339b000    WEAK    FUNC __cxa_finalize

[0x7f47eeef5090]> 
```

And the code:


```
[0x5585de6317f4]> pdf
/ (fcn) sym.func 171
|   sym.func ();
|           ; var int local_6ah @ rbp-0x6a
|           ; var int local_60h @ rbp-0x60
|           ; var int local_30h @ rbp-0x30
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x5585de6317e3 (sym.main)
|           0x5585de6317f4      55             push rbp
|           0x5585de6317f5      4889e5         mov rbp, rsp
|           0x5585de6317f8      4883ec70       sub rsp, 0x70           ; 'p'
|           0x5585de6317fc      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x5585de631805      488945f8       mov qword [local_8h], rax
|           0x5585de631809      31c0           xor eax, eax
|           0x5585de63180b      488d3d120100.  lea rdi, qword str.Enter_a_string_NOW: ; 0x5585de631924 ; "Enter a string NOW: "
|           0x5585de631812      b800000000     mov eax, 0
|           0x5585de631817      e874feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5585de63181c      488d45a0       lea rax, qword [local_60h]
|           0x5585de631820      4889c7         mov rdi, rax
|           0x5585de631823      b800000000     mov eax, 0
|           0x5585de631828      e883feffff     call sym.imp.gets       ; char*gets(char *s)
|           0x5585de63182d      488d55a0       lea rdx, qword [local_60h]
|           0x5585de631831      488d45d0       lea rax, qword [local_30h]
|           0x5585de631835      4889d6         mov rsi, rdx
|           0x5585de631838      4889c7         mov rdi, rax
|           0x5585de63183b      e830feffff     call sym.imp.strcpy     ; char *strcpy(char *dest, const char *src)
|           0x5585de631840      488d45d0       lea rax, qword [local_30h]
|           0x5585de631844      4889c6         mov rsi, rax
|           0x5585de631847      488d3deb0000.  lea rdi, qword str.Copied_string_____s ; 0x5585de631939 ; "Copied string =  %s\n"
|           0x5585de63184e      b800000000     mov eax, 0
|           0x5585de631853      e838feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5585de631858      488d4da0       lea rcx, qword [local_60h]
|           0x5585de63185c      488d4596       lea rax, qword [local_6ah]
|           0x5585de631860      ba04000000     mov edx, 4
|           0x5585de631865      4889ce         mov rsi, rcx
|           0x5585de631868      4889c7         mov rdi, rax
|           0x5585de63186b      e8f0fdffff     call sym.imp.strncpy    ; char *strncpy(char *dest, const char *src, size_t  n)
|           0x5585de631870      488d4596       lea rax, qword [local_6ah]
|           0x5585de631874      4889c6         mov rsi, rax
|           0x5585de631877      488d3dd00000.  lea rdi, qword str.4_first_chars____s ; 0x5585de63194e ; "4 first chars = %s\n"
|           0x5585de63187e      b800000000     mov eax, 0
|           0x5585de631883      e808feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5585de631888      90             nop
|           0x5585de631889      488b4df8       mov rcx, qword [local_8h]
|           0x5585de63188d      6448330c2528.  xor rcx, qword fs:[0x28]
|       ,=< 0x5585de631896      7405           je 0x5585de63189d
|       |   0x5585de631898      e8e3fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x5585de63189d      c9             leave
\           0x5585de63189e      c3             ret
[0x5585de6317f4]> 
```
The disasm looks bigger this time, don't let that scare you, almost everything is already known to us. We start by seeing three variables being detected by r2. 

Then a string is get by gets and strcpy is called, let's see:

```
|           0x5585de63181c      488d45a0       lea rax, qword [local_60h]
|           0x5585de631820      4889c7         mov rdi, rax
|           0x5585de631823      b800000000     mov eax, 0
|           0x5585de631828      e883feffff     call sym.imp.gets       ; char*gets(char *s)
|           0x5585de63182d      488d55a0       lea rdx, qword [local_60h]
|           0x5585de631831      488d45d0       lea rax, qword [local_30h]
|           0x5585de631835      4889d6         mov rsi, rdx
|           0x5585de631838      4889c7         mov rdi, rax
|           0x5585de63183b      e830feffff     call sym.imp.strcpy     ; char *strcpy(char *dest, const char *src)
```
As we can see, the string (user input) will be stored at local_60h, then after that local_60h and local_30h will both be passed to strcpy, at that point we already know that local_60h contains the user input, but local_30h? that'll be the destionation, so the user input will be copied there. Let's debug it
```
[0x5585de6317f4]> db 0x5585de631840
[0x5585de6317f4]> dc
Enter a string NOW: SAMPLE TEXT
hit breakpoint at: 5585de631840
[0x5585de631840]> pdf
[...]
|           0x5585de631838      4889c7         mov rdi, rax
|           0x5585de63183b      e830feffff     call sym.imp.strcpy     ; char *strcpy(char *dest, const char *src)
|           ;-- rip:
|           0x5585de631840 b    488d45d0       lea rax, qword [local_30h]
|           0x5585de631844      4889c6         mov rsi, rax
|           0x5585de631847      488d3deb0000.  lea rdi, qword str.Copied_string_____s ; 0x5585de631939 ; "Copied string =  %s\n"
```
And if we inspect those:

```
[0x5585de631840]> afvd
var local_8h = 0x7fffd173cd38  0x71dec5cbb8695200   .Ri....q
var local_60h = 0x7fffd173cce0  0x5420454c504d4153   SAMPLE T @rsi ascii
var local_30h = 0x7fffd173cd10  0x5420454c504d4153   SAMPLE T @rdi ascii
var local_6ah = 0x7fffd173ccd6  0x0000000000000000   ........ r15
[0x5585de631840]> 

[0x5585de631840]> pxw @ 0x7fffd173cce0
0x7fffd173cce0  0x504d4153 0x5420454c 0x00545845 0x00000000  SAMPLE TEXT.....
0x7fffd173ccf0  0x00000009 0x00000000 0x39a71660 0x00007fa0  ........`..9....
0x7fffd173cd00  0xd173cd68 0x00007fff 0x00f0b5ff 0x00000000  h.s.............
0x7fffd173cd10  0x504d4153 0x5420454c 0x00545845 0x00005585  SAMPLE TEXT..U..
```
The string has been copied :) Also note that both strings are \0 terminated, so strcpy will continue copying until it encounters a \0.

Later on, on the code, strNcpy is called. That is a different function, the "n" there relates to the following: with strncpy the contents of one string are copied to another one but only first n bytes are copied. Let's inspec that:

```
|           0x5585de631858      488d4da0       lea rcx, qword [local_60h]
|           0x5585de63185c      488d4596       lea rax, qword [local_6ah]
|           0x5585de631860      ba04000000     mov edx, 4
|           0x5585de631865      4889ce         mov rsi, rcx
|           0x5585de631868      4889c7         mov rdi, rax
|           0x5585de63186b      e8f0fdffff     call sym.imp.strncpy    ; char *strncpy(char *dest, const char *src, size_t  n)
|           0x5585de631870      488d4596       lea rax, qword [local_6ah]
```
That one is very easy, again, both origin/destiny memory addresses are being passed but 4, the amount of bytes we need to copy, is passed as well.
```
[0x5585de631840]> db 0x5585de631870
[0x5585de631840]> dc
Copied string =  SAMPLE TEXT
hit breakpoint at: 5585de631870
[0x5585de631840]> afvd
var local_8h = 0x7fffd173cd38  0x71dec5cbb8695200   .Ri....q
var local_60h = 0x7fffd173cce0  0x5420454c504d4153   SAMPLE T @rsi ascii
var local_30h = 0x7fffd173cd10  0x5420454c504d4153   SAMPLE T ascii
var local_6ah = 0x7fffd173ccd6  0x00000000504d4153   SAMP.... @rdi ascii
``` 
Only 4 bytes got copied. It is important to remark that in the case of strncpy the null terminator is not inserted by default and that makes sense because maybe our goal is just to "merge" a couple of arrays instead of copying a string to an empty array....

If we want to cut an array we can manually insert a null terminator this way:
```
# include <stdio.h>
# include <string.h>

main(){
 func();
 getchar();

}

func(){

    char text1[40], text2[40], text3[10];
    
    printf("ENTER A STRING: ");
    gets(text1);
 
    strcpy(text2, text1);
    printf("Copied string = %s\n", text2);
    strncpy(text3, text1, 4);
    text3[4] = '\0';
    printf("4 FIRST LETTERS %s\n", text3);
}
```
As we can see, a zero is manually added at the end of the string.
```
       0x561d7710e86b      e8f0fdffff     call sym.imp.strncpy    ; char *strncpy(char *dest, const char *src, size_t  n)
|           0x561d7710e870      c6459a00       mov byte [local_66h], 0
|           0x561d7710e874      488d4596       lea rax, qword [local_6ah]
|           0x561d7710e878      4889c6         mov rsi, rax
|           0x561d7710e87b      488d3dd70000.  lea rdi, qword str.4_FIRST_LETTERS__s ; 0x561d7710e959 ; "4 FIRST LETTERS %s\n"
|           0x561d7710e882      b800000000     mov eax, 0

```
And thats all for now, as said, we'll proceed with more complex structures in the next post.