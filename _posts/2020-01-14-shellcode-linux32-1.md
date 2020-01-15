---
layout: post
title:  "Writting linux32 shellcode from scratch - 1"
author: artikblue
categories: [ reversing, course ]
tags: [shellcode, asm, linux]
image: assets/images/shellcode/shellcode1.png
description: "Writting shellcode for linux 32 bits systems using nasm."
---
Here we go!
#### About this course
In these series of posts we'll walk through the creation and implementation of Linux Shellcode for x32 systems. We'll go from basic operations using syscalls to the implementation of crypters/encoders and we'll be able to use those shellcodes we'll make with our exploits. It is important to note that eventhough a lot of techniques may be quite similar, in here we'll focus on 32 bits linux systems, some topics such as the use of registers change between 32 bit and 64 bit systems, also eventhough the concept is also quite similar, shellcode writting is much easier on Linux than it is on Windows thus starting with shellcode writting in Linux32 is probably the best option.
  
 
I will assume that you have a general knowledge of computer architectures (Von Neumann architecture and so), know what registers are and are able to debug very simple programs, have some basic experience in writting C code for Linux, know a couple or three asm instructions like mov or push, and know what an exploit is.  

Also, these posts will focus on practise, almost all of the heavy theoretical concepts will be referenced with external documents that I recommend you to read.

#### Shellcode and NASM
In general terms, shellcode is a set of asm instructions translated to opcodes (hex values) that often get injected in the stack during the execution of a program to perform a certain operation. Shellcode is very related to exploits as when an exploit achieves execution on a system it will usually try to inject shellcode to compromise the system. Shellcode can be used with exploits but it also can be used in standalone progams such as malware.

NASM or netwide assembler is an assembler written in C for intelx86. Using that we will be able to write and compile asm programs and further on translate them into opcodes for shellcode generation.

#### Program sections
The key concept that we need to understand here is that programs are commonly devided in sections, most of them in .text and .data. The first one contains the executable code and its not often writable during execution time and the other one contains data like variables and data structes and its writable during execution time. Other sections may be present as well but those two are the very basics you need to know by now.  

The suggested lecture here is [understanding the ELF format for binaries](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/)
#### CPU registers

CPU registers are small slots that are capable of storing a value, in the case of a 32 bit architecture, those registers can store 32 bits or 16. Registers are used by the CPU to correctly execute progams. Programs work with data (variables, structures and so on) and this data can be stored in memory and accessed from thereon. However, reading data from and storing data into memory slows down the processor, as it involves complicated processes of sending the data request across the control bus and into the memory storage unit and getting the data through the same channel. To speed up the processor operations, the processor includes some internal memory storage locations, called registers. In the case of an x32 architecture we can find 10 32 bit registers and 6 16 bit registers that can be grouped into general registers, control registers and segment registers. Also the general registers can be divided into data registers, pointer registers and index registers.
  
[A more detailed explaination on what registers are can be found here](https://assemblylanguagetuts.com/x86-assembly-registers-explained)

As I don't want to make these series of posts very theoretical I will assume that you are familiar with what registers are and if you are not I assume that you will browse to the previous link and get familiar with the topic.  

Anyway I will get into more detail with registers as we need it for writting programs further in these posts.

#### Linux syscalls
When low level code like now, we are almost like in total control of what happens within the operating system, we could even be able to directly manipulate devices such as the peripherals to interact with them, but we don't use to do that, there is a lot of code and resources built for use to use, make our lifes easier and simplify our tasks. If we want to write a simple hello world app, in a language such as C we would call the printf function of the standard library for example and we can actually do the same here. The thing here is that there are even easier ways for us to do perform simple tasks like that. 
  
In GNU/Linux systems you can find something called *syscalls* 

Each syscal is made by filling the EAX register with its syscall number and then triggering an interrumption in the following form:

~~~
int 0x80 or SYSENTER
~~~
So, from the user space an interrupt is done by doing (for example) int 0x80 as we saw, then the cpu will go check the IHT (interrupt handler table) and will call the system call handler (a kernel mod), the system call handler will go and figure out what syscall routine we need to execute and will run it.


~~~
eax = system call  number
ebx = 1st argument
ecx = 2nd argument
edx = 3d argument
esi = 4th argument
edi = 5th argument
~~~
The return value of the syscall will be loaded in the EAX register after the operation is completed.
~~~
/usr/include/i386-linux-gnu/unistd_32.h
~~~

#### Basic program structure

![ultrasound](https://artikblue.github.io/assets/images/shellcode/nasm1)

In our case we want a simple program that does two things

1. Print Hello World on the string
2. Exit the program properly

In C we would have our int main function like printf("hello world"); return 0; We don't have a main function in our case, we are directly starting our program from the entry point. There are a couple of syscalls that can be used for what we want to achieve. Those are write() and exit().
  
Write works like that:

~~~
write(file descriptor, buffer, size);
~~~
The first argument is the file descriptor related to where we are going to write, in our case 1 relates to stdout or "the screen". Then buffer represents what do we actually want to write and size its size.  

Exit is more simple:
~~~
exit(int status);
~~~
A 0 would usually mean that the system exited properly but we can use whatever number we want.


#### HelloWorld.asm
The full code for a hello world program is listed below:
~~~
; HelloWorld.asm
; Author: AB

; /usr/include/i386-linux-gnu/asm$ cat unistd_32.h  SYSCALLS

global _start

; text section -> CODE goes here
section .text

; _start identifies the ENTRY POINT of the program
_start:
        ; print "Hello, World"
        mov eax, 0x4 ; write syscall
        mov ebx, 0x1
        mov ecx, message
        mov edx, mlen
        int 0x80

        mov eax, 0x1 ; exit syscall
        mov ebx, 0x5
        int 0x80

        ; exit

; data section -> DATA goes here
section .data
        ; db = define byte, defines a series of bytes
        message: db "Hello, World"
        mlen    equ     $-message

~~~
As you can see the program is divided in the .text and .data sections. The .text section contains executable code and .data contains variables.  

There are two variables listed there on the data section, one *labeled* as message and the other one as mlen. The message variable is defined with "db" that means define byte, basically using that the program will create the string "Hello, World" in memory and the variable "message" will be a pointer to that string [I recommend this stack overflow question if you don't understand that well](https://stackoverflow.com/questions/19526725). The second variable is mlen, that is assigned to a nasm macro with equ $-message, that means that mlen will be equal to the lenght of the previous string. In nasm the $ means the current address according to the assembler. $ - message is the current address of the assembler minus the address of message, which would be the length of the string, that is more practicall than actually having to hardcode it.  

On the text section we find the actual code of the program. The code starts with _start: that defines the *entry point* and what comes next is very simple, first, the number related to the write syscall is passed, then the parameters of the function and finally a syscall is performed with int 0x80. After that, the same is done with the exit syscall.
#### Building the binary
After the code is written it can be converted to a binary with two simple commands. For doing that, we need to perform two operations that will become very common for us from now on. First, we need to compile the program, then we need to link it. Compiling and linking are two tasks that are executed everytime we compile a program by doing something like *gcc -w hello.c -o hello* what happens here is that gcc handles all the stuff by itself and we just get the binary, in this context we have to do it ourselves. Compiling consists of translating a file containing code to a file containing machine code (code that the cpu can execute) linking consists of actually linking all of the machine code (or object files) that we have in our project to generate a final executable that can be ran. [A very good explaination can be found here](https://www.cprogramming.com/compilingandlinking.html)
  
So we generate an ELF32 binary
~~~
nasm -f elf32 -o hw.o HelloWorld.asm 
~~~
And then we link it
~~~
ld -o hw hw.o
~~~
After that we can just run ./hw and we'll see a hello world on the screen.

#### Inspecting the program with radare2
Finally I just want you to notice how simple and efficiant this kind of programs written in pure asm can be. Try to open and analyze this program on radare2.
~~~
[0x08048080]> afl
0x08048080    1 34           entry0
[0x08048080]> pdb
            ;-- section..text:
            ;-- .text:
            ;-- _start:
            ;-- eip:
┌ 34: entry0 ();
│           0x08048080      b804000000     mov eax, 4                  ; [01] -r-x section size 34 named .text
│           0x08048085      bb01000000     mov ebx, 1
│           0x0804808a      b9a4900408     mov ecx, loc.message        ; 0x80490a4 ; "Hello, World\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
│           0x0804808f      ba0c000000     mov edx, 0xc                ; loc.mlen
│           0x08048094      cd80           int 0x80
│           0x08048096      b801000000     mov eax, 1
│           0x0804809b      bb05000000     mov ebx, 5
└           0x080480a0      cd80           int 0x80
[0x08048080]> 
~~~
What we see here is exactly the same thing we wrote, nothing more. As we are only using nasm with syscalls and not C with libraries such as stdio.h our code is way more clean, when we start using libraries such as that one I mentioned, our binaries get bigger and more hard to understand. So with nasm and syscalls it will be hard and time consuming to write complex programs but we'll have the absolute control of whats going on, with higher level languages the opposite will happen.