---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 1"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_1.png
featured_image: assets/images/radare2/radare2_1.png
---


#### About this course
This series of post that I'm starting with this one will cover the fundamentals of reverse engineering with the "popular" radare2 framework. What I want to do here is to walk you through a diverse set of examples of C-written binaries that will cover the most common algorithms and data structures you can find in programs out there, so at the end you will be able to identify them and work with them. This won't be an advanced/pro course but it will start from the very bottom and will cover far more than the average free course/tutorial. 
  
On these series of posts we'll start with an C source file / algorithm, compile it in both 32 bits and 64 bits systems and then reverse engineer it using radare2, so you'll be able to appreciate the differences between 32 and 64 bit binaries. Once we cover the fundamentals of reversing we'll focus on x64.
  
I assume that you have some fundamental knowledge about computer arquitectures and know some basic asm instructions such as mov, push and such. I also assume that you already know what radare2 is and thus want to *finally* learn how to use it.
#### Getting radare2

Most of the people who use radare2 use it on Linux systems, as from there you can analyze all sorts of binaries and if you want to debug them you can connect to a remote debug session or use gbd on Linux. In here we'll use r2 on Linux most of the time and move it to Windows when needed.

Radare2 supports a ton of arquitectures from from x64 to arduinos or tamagochis and you can analyze binaries related to those arquitectures from the comfort of your ubuntu system or whatever you use. 
  
Said that, the best way to get radare2, as the webpage itself suggests is to clone it from the repositories:
~~~
git clone https://github.com/radare/radare2
cd radare2
sys/install.sh   # just run this script to update r2 from git
~~~
You can also install it from the apt/rpm/yaourt/whatever repo in most distributions with something like:

~~~
sudo apt-get install radare2
~~~

And if you wish to use it on windows you can [download the windows setup](https://rada.re/r/down.html) from its website.

#### Hello world
Every programming journy begins with the classical hello world program and this one won't be less. And a hello world in C language will look exactly like that:
```

#include <stdio.h>
int main() {
   printf("Hello, World!");
   return 0;
}
```

A program like that can be easily compiled using the GCC compiler like this:

~~~
gcc -w hello_world.c -o hello_word
~~~
And if we run it we are basically going to get a "Hello, World!" on our screen and that will be all, very simple but we need to begin with something :)
  
Once the program is compiled we can open it with r2 by using "radare2 program" where program is the program you want to analyze, r2 is also an alias of radare2 so you can use it instead if you want. Once the binary is loaded, we need radare to parse the program; running aaaa will analize the binary and detect data structures, functions calls and these kinds of elements. If you want to better understand how this works [this answer on stackoverflow](https://reverseengineering.stackexchange.com/questions/19895/radares-aaaa-and-aa-what-does-it-do-exactly) is quite explainatory.
~~~
lab@lab-VirtualBox:~$ radare2 c_examples/bin/hello_world 
 -- Use V! to enter into the visual panels mode (dwm style)
[0x08048310]> aaaa
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
[x] Finding function preludes
[x] Enable constraint types analysis for variables
[0x08048310]> 
~~~
Once the program is loaded and parsed, plenty of actions can be done on it, such as listing strings, disassembling code blocks and more. One of the most common things you'll want to do when you get your hands on an unknown binary is to get a list of its functions. You can do it using the afl command.
~~~
[0x08048310]> afl
0x08048310    1 33           entry0
0x080482f0    1 6            sym.imp.__libc_start_main
0x08048350    4 43           sym.deregister_tm_clones
0x08048380    4 53           sym.register_tm_clones
0x080483c0    3 30           entry.fini0
0x080483e0    4 43   -> 40   entry.init0
0x080484a0    1 2            sym.__libc_csu_fini
0x08048340    1 4            sym.__x86.get_pc_thunk.bx
0x080484a4    1 20           sym._fini
0x08048440    4 93           sym.__libc_csu_init
0x0804840b    1 46           main
0x080482e0    1 6            sym.imp.printf
0x080482ac    3 35           sym._init
[0x08048310]> 
~~~
In examples such as this one, the most interesting function is "main". Entry* functions can be interesting as well but as this is a hello world program in functions like those you'll probably find a bunch of code you won't understand at all at this moment (some internal stuff added by the compiler) so we can leave them for now. Other functions we are seeing in this example are related to the C libraries/calls used by the progam (as the printf call you'll probably identify there).
  
Another interesting initial thing we can do here is for example get the general information about the binary with *iI*:
~~~
[0x08048310]> iI
arch     x86
baddr    0x8048000
binsz    6115
bintype  elf
bits     32
canary   false
class    ELF32
compiler GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609
crypto   false
endian   little
havecode true
intrp    /lib/ld-linux.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  Intel 80386
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true

[0x08048310]> 
~~~
That will prompt values such as the architecture or the compiler. Those values are always interesting so we can know what we are dealing with and start discarting strategies focusing on what matters.
  
We can also list the imports with *ii*
~~~
[0x08048310]> ii
[Imports]
nth                vaddr              bind   type              name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
577730550794551297 0xb6f9994600000000 FUNC   printf            
2                  0xb6f9994d00000000 NOTYPE __gmon_start__    
577730619514028035 0xb6f9994600000000 FUNC   __libc_start_main 
~~~
In this particular case, by know we should be sure that we are dealing with a simple program written in C.
  
Another command of our interest may be the *iz* one. That will list all of the strings contained within the data section of the program (*izz* will list strings in the whole file). That command is specially useful when dealing with simple crackmes (so we can identify hardcoded passwords).  

In general terms knowing the strings inside a program is helpful when it comes to getting a general idea of "what the program is about".
~~~
[0x08048310]> iz
[Strings]
nth           paddr             vaddr       len size     section type          string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
5222680231936 0x80484c000000000 0xd00000000 14  34461128 ascii   Hello, World! bin.strings

[0x08048310]> 
~~~
As we can see, iz detects the "Hello, World!" string, the string that appears everytime we run the program. Radare also tells us about the section (ascii) and the location of the string.  
  
Now that we know some of the very basic fundamentals let's actually reverse the program and try to figure out what and how it does. 
~~~
[0x08048310]> sf main
[0x0804840b]> pdb
            ; DATA XREF from entry0 @ 0x8048327
┌ 46: int main (int32_t arg_4h, char **argv, char **envp);
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_4h @ esp+0x24
│           0x0804840b      8d4c2404       lea ecx, [arg_4h]
│           0x0804840f      83e4f0         and esp, 0xfffffff0
│           0x08048412      ff71fc         push dword [ecx - 4]
│           0x08048415      55             push ebp
│           0x08048416      89e5           mov ebp, esp
│           0x08048418      51             push ecx
│           0x08048419      83ec04         sub esp, 4
│           0x0804841c      83ec0c         sub esp, 0xc
│           0x0804841f      68c0840408     push str.Hello__World       ; 0x80484c0 ; "Hello, World!" ; const char *format
│           0x08048424      e8b7feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08048429      83c410         add esp, 0x10
│           0x0804842c      b800000000     mov eax, 0
│           0x08048431      8b4dfc         mov ecx, dword [var_4h]
│           0x08048434      c9             leave
│           0x08048435      8d61fc         lea esp, [ecx - 4]
└           0x08048438      c3             ret
[0x0804840b]> 
~~~
The first thing that we have to understand here is that, we are inspecting main, and main is a function, so it has to return to somewhere and it may receive arguments or need space for local variables, operations related to those aspects are performed at the beggining and the end of the code.
  

The part that we'll have to focus on here starts with push str.Hello__World and then the call to printf. In 32 bits systems the way of passing parameters to functions consists of pushing those parameters to the stack and then executing a call operation on the address of the function. So something like "printf(a);" in C would be a "push a; call printf" in asm. [So what about the rest of the code?](https://stackoverflow.com/questions/36046201/why-do-we-push-ebp-and-mov-ebp-esp-in-the-callee-in-assembly) Well, the first part of the code is related establishing a new [stack frame](http://www.cs.uwm.edu/classes/cs315/Bacon/Lecture/HTML/ch10s07.html) and a stack frame is nothing more than a section of the code that will contain local variables of the function, arguments passed and values such as that. The end of the code


#### x64 binaries and its particularities
Let's repeat the process now but compiling the same program and opening it in r2 in an x64 system.
~~~
[0x00000540]> sf sym.main
[0x0000064a]> pdb
            ;-- main:
/ (fcn) sym.main 28
|   sym.main ();
|              ; DATA XREF from 0x0000055d (entry0)
|           0x0000064a      55             push rbp
|           0x0000064b      4889e5         mov rbp, rsp
|           0x0000064e      488d3d9f0000.  lea rdi, qword str.Hello__World ; 0x6f4 ; "Hello, World!" ; const char * format
|           0x00000655      b800000000     mov eax, 0
|           0x0000065a      e8c1feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0000065f      b800000000     mov eax, 0
|           0x00000664      5d             pop rbp
\           0x00000665      c3             ret
[0x0000064a]> 
~~~
The main difference between a x32 program and a x64 one in small examples like this one is that, as you may have seen parameters to functions aren't passed by the stack. In x64 programs like this one, parameters are passed using registers such as rdi, rsi, rdx, rcx, r8 and r9 in that order. We'll keep walking through the x64 architecture with clear and specific examples but [you may want to consider reading a cheatsheet like this one to gain a more solider understanding on topics such as this last one](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)
  
There is nothing much more to comment by now.

If we look at the code, in this case, at the beggining of the code, we can appreciate a "push rbp, mov ebp, rsp" This is related to the stack alignment. Then what comes next is way more clear, with lea we load the effective address of the null terminated string "Hello, World!" to the RDI register, then we load the hex value 0 to eax and we proceed to call printf(). We load eax with 0 mainly because the printf function has variable arguments such as the string and a whole lot of format related parameters among others, printf can work with vector registers, for example when doing printf("%f", 1.0f) then the progam will have to set eax to 1 to indicate that. [This stackoverflow question offers a very clear explanation on the mov eax,0 issue](https://stackoverflow.com/questions/6212665/why-is-eax-zeroed-before-a-call-to-printf)
  
At the end of the program, we see a mov eax, 0 then pop rbp and a ret being executed. The first the the first one seats eax to 0 as it gets the program ready to do a "return 0" then the second one restores the stack to its original state via picking the original stack frame value to rbp. Then ret just returns the function exiting it with 0 value.

#### Commands used
Today we basically used those commands:

| Command         | Description                          |
|-----------------|--------------------------------------|
| aaaa            | Fully analyze the binary             |
| afl             | List all the functions in the binary |
| ii              | List imports                         |
| iI              | Information about the binary         |
| iz              | List strings in the binary           |
| sf   function   | Seek to a function                   |
| pdb             | Print disassembly of the basic block |







