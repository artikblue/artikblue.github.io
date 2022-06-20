---
layout: post
title:  Reverse engineering x64 binaries with Radare2 - 14 - I (linux systems programming; theory, syscalls, files and ESIL)
tags: reversing c radare
image: '/images//radare2/radare2_14.png'
date: 2020-05-15 15:01:35 -0700
---

What's up family, today we are going one step further in reversing. From our fist reversing tutorial untill now, we saw the very basics of reverse engineering, particularly reverse engineering focused on x86-64 bits linux binaries written in C. Eventhough our main target were c written binaries for linux the techniques and tricks we went through are pretty common and can be used let's say when reversing 32 bits windows C++ binaries for example (at the end we were only dealing with libraries such as stdio and strings that are common in both Win/Linux). On the other hand we've been using radare2, same thing, the knowledge we got can be applied when doing reversing with other tools such as ghidra, IDA, binaryninja, etc. 

As said, today we are moving to the next level. As we start to get deeper into more advanced topics like systems programming, advanced topics on memory management, malware related stuff or exploiting and shellcoding, we encounter that different systems such as Windows and Linux do handle stuff (internally) in a different way. So after this point I'm going to walk you through some new topics on reversing, mostly related to systems internals and malware techniques showing you how the thing is done in both Linux and Windows separately.

In this particular post, we are going to walk through the concept of the Linux kernel and very basic syscalls.


#### Kernel space and User space

As you should know, the kernel is the real hearth of the operating system it provides services such as process and memory management or the file system and the tcp stack. It provides access control over the files and memory and also provides us with the modules / drivers that deal with external devices such as the keyboard or the mouse. So the kernel (as a concept) is located on top of the hardware and directly deals with stuff like the ram memory, the disk, the network access etc and also deals with the programs, setting up the environment and dealing witht he resources they need such as space in memory or access to IO devices.

So, the program that is purely related to the operating system kernel, the one that we just presented works in the so called "kernel space" that is an area of the memory where we can only find kernel code/data. Why do we need that separation? For many reasons really, but think about the security, the code that is related to the kernel, the very core of the operating system needs to have full control over the machine, but your average program that does a couple of calculations and outputs a result certainly not, those programs need to be separated for securitty reasons and as the kernel runs in its own mem space and is the kernel the one that launches user programs it has the full control to make them run in the user space, the kernel is able to mangle in both spaces and the user programs do only run on user space. Anyway, if you are reading this, a reverse engineering course, at this point, you should already know about the topic.

But why are we talking about this? At the end we are on a reverse engineering course huh? Well, when we are analyzing programs, we may see functions that clearly deal with external devices or memory managemtn, think about printf() it puts content on the screen, then look at fopen, it writes a file on the disk or malloc that creates space in memory, those need to interact with the kernel in some way to ask it for the required action. Not all functions need the kernel for work, you may have the sqrt() function that just returns the square root of a number, it just takes a number (through rsi) calculates something and returns another one (through rax), the is nothing done in memory, disk, network, screen... that function won't ask the kernel for anything and will depend only on user space code.

So, in systems that work on top of the Linux kernel, any operation that deals with cpu, memory, io devices, filesystem and so is done under a system call. Think of system calls or syscalls as special functions that require the kernel for a certain action. An example of a syscall, that we'll inspect on this post is the write() syscall. Write basically writes data to a device, being that device, the screen, a file, a socket or whatever and yes, on linux "everything is a device". If you want to write text on the screen you can use write() but you can also use printf(), the thing is that inside printf() write() is being called, printf just calls write in a fancy way (allowing us format definition and such) 




#### System calls and error handling

Let's now perform our first syscall. On this example we will use the open() syscall to create a file and then the write() syscall to write content to the file and also to the screen.

```C
#include <fcntl.h>

void main(){
    int fd = open("foo", O_WRONLY | O_CREAT, 0644);
    write(fd, "hello_world", 11);
    write(1,"hello world", 11);
    close(fd);

    printf("\nhello world2\n");
}

```
As you can see, at first, open is called to open "foo" file, it returns an int value that is assigned to the fd var, open returns the file descriptor of the file it just opened. We'll talk about file descriptors right after but for now just know that a file descriptor is a reference to a file/external device/socket/whatever we can read or write data from/to. Then write gets called with that number and some text as parameter (11 being the size of that text).

Let's inspect the function header: http://man7.org/linux/man-pages/man2/write.2.html

ssize_t write(int fd, const void *buf, size_t count);

So the parameters for the function work fine but wait, what is the a ssize_t type? Why just not define that return value as some int and that's all? The kernel uses custom data types as ssize_t for portability reasons, programs relying on the kernel will always kind of blindly refer to types such as ssize_t, the kernel will deal with the actual val internally, in this case a ssize_t is basically a signed long, but it can be another thing on a future version of the kernel, does not matter we'll always refeer to that.

We also see that open is being called with two flags here O_WRONLY added to O_CREAT so the file will be accessed for write only and will be created if it does not exist, remember the past tutorial about bitwise operations? Now you see how flags are being passed on a real example. Then 644 is related to the unix permissions on the file, I won't go much into details as I suppose that you already know about permissions. 

After that, we see write being called again, this time with 1 as the fd. There are three standard (posix) file descriptors that you should be aware off as they are present in every unix process: 0 is the standard input (what the user enters to the program normally via the keyboard), 1 is the standard output (screen) and 2 is the standard error. So now that second write over there should make more sense to you.

Let's now jump into radare2:
```
[0x558c82dc071a]> pdf
            ; DATA XREF from entry0 @ 0x558c82dc062d
┌ 122: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_4h @ rbp-0x4
│           0x558c82dc071a      55             push rbp
│           0x558c82dc071b      4889e5         mov rbp, rsp
│           0x558c82dc071e      4883ec10       sub rsp, 0x10
│           0x558c82dc0722      baa4010000     mov edx, 0x1a4          ; 420
│           0x558c82dc0727      be41000000     mov esi, 0x41           ; 'A' ; 65
│           0x558c82dc072c      488d3df10000.  lea rdi, [0x558c82dc0824] ; "foo"
│           0x558c82dc0733      b800000000     mov eax, 0
│           0x558c82dc0738      e8b3feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x558c82dc073d      8945fc         mov dword [var_4h], eax
│           0x558c82dc0740      8b45fc         mov eax, dword [var_4h]
│           0x558c82dc0743      ba0b000000     mov edx, 0xb            ; 11
│           0x558c82dc0748      488d35d90000.  lea rsi, [0x558c82dc0828] ; "hello_world"
│           0x558c82dc074f      89c7           mov edi, eax
│           0x558c82dc0751      b800000000     mov eax, 0
│           0x558c82dc0756      e875feffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│           0x558c82dc075b      ba0b000000     mov edx, 0xb            ; 11
│           0x558c82dc0760      488d35cd0000.  lea rsi, str.hello_world ; 0x558c82dc0834 ; "hello world"
│           0x558c82dc0767      bf01000000     mov edi, 1
│           0x558c82dc076c      b800000000     mov eax, 0
│           0x558c82dc0771      e85afeffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│           0x558c82dc0776      8b45fc         mov eax, dword [var_4h]
│           0x558c82dc0779      89c7           mov edi, eax
│           0x558c82dc077b      b800000000     mov eax, 0
│           0x558c82dc0780      e85bfeffff     call sym.imp.close      ; int close(int fildes)
│           0x558c82dc0785      488d3db40000.  lea rdi, str.hello_world2 ; 0x558c82dc0840 ; "\nhello world2"
│           0x558c82dc078c      e82ffeffff     call sym.imp.puts       ; int puts(const char *s)
│           0x558c82dc0791      90             nop
│           0x558c82dc0792      c9             leave
└           0x558c82dc0793      c3             ret
[0x558c82dc071a]> 
```

So on the open we see 420 dec = 0644 octal being assed as weel as the file name and 0x41 that is the combination of those two flags. Then after calling open, we get the file descriptor:

```
│           0x558c82dc0738      e8b3feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x558c82dc073d      8945fc         mov dword [var_4h], eax

[0x558c82dc073d]> dr eax
0x00000003
```
Three is the file descriptor for our file, it makes sense as 0,1 and 2 are used by default, 3 is the next one available.



Then that file descriptor is sent to write:

```
│           0x558c82dc0740      8b45fc         mov eax, dword [var_4h]
│           0x558c82dc0743      ba0b000000     mov edx, 0xb            ; 11
│           0x558c82dc0748      488d35d90000.  lea rsi, [0x558c82dc0828] ; "hello_world"
│           0x558c82dc074f      89c7           mov edi, eax
│           0x558c82dc0751      b800000000     mov eax, 0
│           0x558c82dc0756      e875feffff     call sym.imp.write 
```
And for the last write just a simple 1 is being sent:
```
│           0x558c82dc075b      ba0b000000     mov edx, 0xb            ; 11
│           0x558c82dc0760      488d35cd0000.  lea rsi, str.hello_world ; 0x558c82dc0834 ; "hello world"
│           0x558c82dc0767      bf01000000     mov edi, 1
│           0x558c82dc076c      b800000000     mov eax, 0
│           0x558c82dc0771      e85afeffff     call sym.imp.write 
```
Let's now compare write with printf(). Writting to screen (stdout) with printf is as easy as:

```C
#include <stdio.h>

void main(){

        printf("ssssssssyscall\n");

}
```
And then inside radare, we just see a puts here, not a write
```
[0x558589dc963a]> pdf
            ; DATA XREF from entry0 @ 0x558589dc954d
┌ 19: int main (int argc, char **argv, char **envp);
│           0x558589dc963a      55             push rbp
│           0x558589dc963b      4889e5         mov rbp, rsp
│           0x558589dc963e      488d3d8f0000.  lea rdi, str.ssssssssyscall ; 0x558589dc96d4 ; "ssssssssyscall"
│           0x558589dc9645      e8c6feffff     call sym.imp.puts       ; int puts(const char *s)
│           0x558589dc964a      90             nop
│           0x558589dc964b      5d             pop rbp
└           0x558589dc964c      c3             ret
[0x558589dc963a]> dcs*

```
But just note that the write syscall is being used on the inside of puts! With radare2, you can trace all of the syscalls by using dcs*, like this:

```
child stopped with signal 133
--> SN 0x7f7b6205a154 syscall 1 write (0x1 0x55858a4e3260 0xf)
ssssssssyscall
child stopped with signal 133
--> SN 0x7f7b6202ee06 syscall 231 exit_group (0xf)
child exited with status 15

==> Process finished
```
And as you can see write is being called right before our string gets on the screen. Again functions such as printf included on the stdio.h lib are just abstractions to make our life easy providing us with extra functionality, they deal with syscalls on the inside.

Also note that, when running the write syscall, no internal buffer is used (unlike we saw when using Fwrite function) so no heap space is created after write, this function directly dumps the data to the fd and the kernel internally creates the content inside the file.

```
[0x558c82dc075b]> dmh
No Heap section
```
```C
#include <fcntl.h>
#include <stdio.h>

void main(){
    fd = open("foo", O_WRONLY | O_CREAT, 0644);
    if(fd >= 0){
        write(fd, "hello_world", 11);
        close(fd);
    }
    else{
        printf("error number %d\n", errno);
        perror("foo");
        exit(1);
    }
}
```

#### File descriptors

Let's talk a little bit about file descriptors as this is a concept that we'll see a lot during our reversing adventures and it may be not so clear for everybody. 

In Unix and related computer operating systems, a file descriptor or fd is an abstract indicator (handle) used to access a file or other input/output resource, such as a pipe or network socket. In general terms, anything you can read information from or dump information to can be represented by a file descrriptor. 

In the traditional implementation of Unix, file descriptors index into a per-process file descriptor table maintained by the kernel, that in turn indexes into a system-wide table of files opened by all processes, called the file table. This table records the mode with which the file (or other resource) has been opened: for reading, writing, appending, and possibly other modes. It also indexes into a third table called the inode table that describes the actual underlying files.[3] To perform input or output, the process passes the file descriptor to the kernel through a system call, and the kernel will access the file on behalf of the process. The process does not have direct access to the file or inode tables.

In Unix-like systems, file descriptors can refer to any Unix file type named in a file system. As well as regular files, this includes directories, block and character devices (also called "special files"), Unix domain sockets, and named pipes. File descriptors can also refer to other objects that do not normally exist in the file system, such as anonymous pipes and network sockets. We'll talk about those devices such as sockets or pipes a lot during these walkthrough on reversing advanced topics.

Do you remember about our past tutorial, when we talked about dealing with files using fwrite and fread? So the FILE data structure in the C standard I/O library usually includes a low level file descriptor for the object in question on Unix-like systems, so the FILE object and fwrite/fread do use write and read syscalls on the inside. Not everything should make more sense to you.

The following table shows how the system deals with file descriptors for read/write operations on files using the mentioned table:

https://en.wikipedia.org/wiki/File_descriptor

![fd](https://upload.wikimedia.org/wikipedia/commons/thumb/f/f8/File_table_and_inode_table.svg/300px-File_table_and_inode_table.svg.png "Unix fd table")




#### File copying at system level

Let's dig a bit more inside syscalls. So, if there's a write call, there should be a read one, right? Consider the following example:

```C
#include <fcntl.h>
#include <stdlib.h>

#define BSIZE 16384

void main(){
    int fin, fout;
    char buf[BSIZE];
    int count;

    if ((fin = open("foo", O_RDONLY)) < 0){
        perror("foo");
        exit(2);
    }
    if((ffout = open("bar", O_WRONLY | O_CREAT, 0644)) < 0){
        perror("bar");
        exit(2);
    }
    while ((count = read(fin, buf, BSIZE)) > 0)
        write(fout, buf, count);

    close(fin);
    close(fout);
}
```
So, the following example basically opens two files, one for reading (O_RDONLY) and the other one for writting (O_WRONLY), the program will check if those files get opened well and then it will read bytes from one file and dump them on the other one.

Let's inspect the program yeee

```
[0x5575eada481a]> pdf
            ; DATA XREF from entry0 @ 0x5575eada472d
┌ 300: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_401ch @ rbp-0x401c
│           ; var int64_t var_4018h @ rbp-0x4018
│           ; var int64_t var_4014h @ rbp-0x4014
│           ; var int64_t var_4010h @ rbp-0x4010
│           ; var int64_t var_8h @ rbp-0x8
│           0x5575eada481a      55             push rbp
│           0x5575eada481b      4889e5         mov rbp, rsp
│           0x5575eada481e      4881ec204000.  sub rsp, 0x4020
│           0x5575eada4825      64488b042528.  mov rax, qword fs:[0x28]
│           0x5575eada482e      488945f8       mov qword [var_8h], rax
│           0x5575eada4832      31c0           xor eax, eax
│           0x5575eada4834      be00000000     mov esi, 0
│           0x5575eada4839      488d3d940100.  lea rdi, [0x5575eada49d4] ; "foo"
│           0x5575eada4840      b800000000     mov eax, 0
│           0x5575eada4845      e886feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x5575eada484a      8985e4bfffff   mov dword [var_401ch], eax
│           0x5575eada4850      83bde4bfffff.  cmp dword [var_401ch], 0
│       ┌─< 0x5575eada4857      791b           jns 0x5575eada4874
│       │   0x5575eada4859      488d3d740100.  lea rdi, [0x5575eada49d4] ; "foo"
│       │   0x5575eada4860      b800000000     mov eax, 0
│       │   0x5575eada4865      e876feffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5575eada486a      bf02000000     mov edi, 2
│       │   0x5575eada486f      e87cfeffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5575eada4874      baa4010000     mov edx, 0x1a4          ; 420
│           0x5575eada4879      be41000000     mov esi, 0x41           ; 'A' ; 65
│           0x5575eada487e      488d3d530100.  lea rdi, [0x5575eada49d8] ; "bar"
│           0x5575eada4885      b800000000     mov eax, 0
│           0x5575eada488a      e841feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x5575eada488f      8985e8bfffff   mov dword [var_4018h], eax
│           0x5575eada4895      83bde8bfffff.  cmp dword [var_4018h], 0
│       ┌─< 0x5575eada489c      793d           jns 0x5575eada48db
│       │   0x5575eada489e      488d3d330100.  lea rdi, [0x5575eada49d8] ; "bar"
│       │   0x5575eada48a5      b800000000     mov eax, 0
│       │   0x5575eada48aa      e831feffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5575eada48af      bf02000000     mov edi, 2
│       │   0x5575eada48b4      e837feffff     call sym.imp.exit       ; void exit(int status)
│      ┌──> 0x5575eada48b9      8b95ecbfffff   mov edx, dword [var_4014h]
│      ╎│   0x5575eada48bf      488d8df0bfff.  lea rcx, [var_4010h]
│      ╎│   0x5575eada48c6      8b85e8bfffff   mov eax, dword [var_4018h]
│      ╎│   0x5575eada48cc      4889ce         mov rsi, rcx
│      ╎│   0x5575eada48cf      89c7           mov edi, eax
│      ╎│   0x5575eada48d1      b800000000     mov eax, 0
│      ╎│   0x5575eada48d6      e8b5fdffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│      ╎└─> 0x5575eada48db      488d8df0bfff.  lea rcx, [var_4010h]
│      ╎    0x5575eada48e2      8b85e4bfffff   mov eax, dword [var_401ch]
│      ╎    0x5575eada48e8      ba00400000     mov edx, 0x4000
│      ╎    0x5575eada48ed      4889ce         mov rsi, rcx
│      ╎    0x5575eada48f0      89c7           mov edi, eax
│      ╎    0x5575eada48f2      b800000000     mov eax, 0
│      ╎    0x5575eada48f7      e8c4fdffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
│      ╎    0x5575eada48fc      8985ecbfffff   mov dword [var_4014h], eax
│      ╎    0x5575eada4902      83bdecbfffff.  cmp dword [var_4014h], 0
│      └──< 0x5575eada4909      7fae           jg 0x5575eada48b9
│           0x5575eada490b      8b85e4bfffff   mov eax, dword [var_401ch]
│           0x5575eada4911      89c7           mov edi, eax
│           0x5575eada4913      b800000000     mov eax, 0
│           0x5575eada4918      e893fdffff     call sym.imp.close      ; int close(int fildes)
│           0x5575eada491d      8b85e8bfffff   mov eax, dword [var_4018h]
│           0x5575eada4923      89c7           mov edi, eax
│           0x5575eada4925      b800000000     mov eax, 0
│           0x5575eada492a      e881fdffff     call sym.imp.close      ; int close(int fildes)
│           0x5575eada492f      90             nop
│           0x5575eada4930      488b45f8       mov rax, qword [var_8h]
│           0x5575eada4934      644833042528.  xor rax, qword fs:[0x28]
│       ┌─< 0x5575eada493d      7405           je 0x5575eada4944
│       │   0x5575eada493f      e85cfdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x5575eada4944      c9             leave
└           0x5575eada4945      c3             ret
[0x5575eada481a]> 
```
First of all, those two files get open:
```
│           0x5575eada4845      e886feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x5575eada484a      8985e4bfffff   mov dword [var_401ch], eax
│           0x5575eada4850      83bde4bfffff.  cmp dword [var_401ch], 0
│       ┌─< 0x5575eada4857      791b           jns 0x5575eada4874
│       │   0x5575eada4859      488d3d740100.  lea rdi, [0x5575eada49d4] ; "foo"
│       │   0x5575eada4860      b800000000     mov eax, 0
│       │   0x5575eada4865      e876feffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5575eada486a      bf02000000     mov edi, 2
│       │   0x5575eada486f      e87cfeffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5575eada4874      baa4010000     mov edx, 0x1a4          ; 420
│           0x5575eada4879      be41000000     mov esi, 0x41           ; 'A' ; 65
│           0x5575eada487e      488d3d530100.  lea rdi, [0x5575eada49d8] ; "bar"
│           0x5575eada4885      b800000000     mov eax, 0
│           0x5575eada488a      e841feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x5575eada488f      8985e8bfffff   mov dword [var_4018h], eax
│           0x5575eada4895      83bde8bfffff.  cmp dword [var_4018h], 0
```
If we debug the code, we'll see how 2 more file descriptors are handled by the process after those opens:
```
[0x5575eada4895]> dr eax
0x00000004
[0x5575eada481a]> 
```
The last open returns with the file descriptor 4, as fds get assigned one after the other.

So it is easy to guess that the second file fd (fout) will be assigned to var_4018h the first one (in) will go to var_401ch.

Then we see the read/write loop, that reads from the first file and dumps to the second one.

```
│      ╎    0x5575eada48f7      e8c4fdffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
│      ╎    ;-- rip:
│      ╎    0x5575eada48fc b    8985ecbfffff   mov dword [var_4014h], eax
│      ╎    0x5575eada4902      83bdecbfffff.  cmp dword [var_4014h], 0


[0x5575eada48fc]> dr rax
0x0000000b
```
Read returns 11dec, the number of bytes that have been readed and loaded inside the corresponding buffer: 

```
[0x5575eada48fc]> afvd
var var_8h = 0x7ffc6daf1518 = (qword)0x2f161817be55cb00
var var_401ch = 0x7ffc6daed504 = (qword)0x0000000400000003
var var_4018h = 0x7ffc6daed508 = (qword)0x0000000000000004
var var_4010h = 0x7ffc6daed510 = (qword)0x6f775f6f6c6c6568
var var_4014h = 0x7ffc6daed50c = (qword)0x6c6c656800000000
[0x5575eada48fc]> pxw @ 0x7ffc6daed510
0x7ffc6daed510  0x6c6c6568 0x6f775f6f 0x00646c72 0x00000000  hello_world.....
0x7ffc6daed520  0x00000000 0x00000000 0x00000000 0x00000000  ................
```
As shown, variables include file descriptors and a pointer to the buffer for read

The read syscall will get the specified number of bytes (or till the end of the file if less) and dump them on a buffer. Thats it, this is how it works.

But read and write are not the only way which we can use to transfer information between files, syscalls such as sendfile will allow us to do the same without having to use any buffer at all.

Consider the following program:
```c
#include <fcntl.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int src;               /* file descriptor for source file */
    int dest;              /* file descriptor for destination file */
    struct stat stat_buf;  /* hold information about input file */
    off_t offset = 0;      /* byte offset used by sendfile */

    /* check that source file exists and can be opened */
    src = open(argv[1], O_RDONLY);

    /* get size and permissions of the source file */
    fstat(src, &stat_buf);

    /* open destination file */
    dest = open(argv[2], O_WRONLY|O_CREAT, stat_buf.st_mode);

    /* copy file using sendfile */
    sendfile (dest, src, &offset, stat_buf.st_size);

    /* clean up and exit */
    close(dest);
    close(src);

    return 0;
}
```
We see a bunch of new stuff here. First of all, this program reads arguments from the user, then the fstat syscall is executed and finally we do sendfile. This one is interesting, let's reverse it:
```
[0x5606844bd78a]> pdf
            ; DATA XREF from entry0 @ 0x5606844bd69d
┌ 258: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_c0h @ rbp-0xc0
│           ; var int64_t var_b4h @ rbp-0xb4
│           ; var int64_t var_b0h @ rbp-0xb0
│           ; var int64_t var_ach @ rbp-0xac
│           ; var int64_t var_a8h @ rbp-0xa8
│           ; var int64_t var_a0h @ rbp-0xa0
│           ; var int64_t var_88h @ rbp-0x88
│           ; var int64_t var_70h @ rbp-0x70
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x5606844bd78a      55             push rbp
│           0x5606844bd78b      4889e5         mov rbp, rsp
│           0x5606844bd78e      4881ecc00000.  sub rsp, 0xc0
│           0x5606844bd795      89bd4cffffff   mov dword [var_b4h], edi ; argc
│           0x5606844bd79b      4889b540ffff.  mov qword [var_c0h], rsi ; argv
│           0x5606844bd7a2      64488b042528.  mov rax, qword fs:[0x28]
│           0x5606844bd7ab      488945f8       mov qword [var_8h], rax
│           0x5606844bd7af      31c0           xor eax, eax
│           0x5606844bd7b1      48c78558ffff.  mov qword [var_a8h], 0
│           0x5606844bd7bc      488b8540ffff.  mov rax, qword [var_c0h]
│           0x5606844bd7c3      4883c008       add rax, 8
│           0x5606844bd7c7      488b00         mov rax, qword [rax]
│           0x5606844bd7ca      be00000000     mov esi, 0
│           0x5606844bd7cf      4889c7         mov rdi, rax
│           0x5606844bd7d2      b800000000     mov eax, 0
│           0x5606844bd7d7      e884feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x5606844bd7dc      898550ffffff   mov dword [var_b0h], eax
│           0x5606844bd7e2      488d9560ffff.  lea rdx, [var_a0h]
│           0x5606844bd7e9      8b8550ffffff   mov eax, dword [var_b0h]
│           0x5606844bd7ef      4889d6         mov rsi, rdx
│           0x5606844bd7f2      89c7           mov edi, eax
│           0x5606844bd7f4      b800000000     mov eax, 0
│           0x5606844bd7f9      e812010000     call sym.fstat          ; int fstat(int fildes, void *buf)
│           0x5606844bd7fe      8b9578ffffff   mov edx, dword [var_88h]
│           0x5606844bd804      488b8540ffff.  mov rax, qword [var_c0h]
│           0x5606844bd80b      4883c010       add rax, 0x10           ; 16
│           0x5606844bd80f      488b00         mov rax, qword [rax]
│           0x5606844bd812      be41000000     mov esi, 0x41           ; 'A' ; 65
│           0x5606844bd817      4889c7         mov rdi, rax
│           0x5606844bd81a      b800000000     mov eax, 0
│           0x5606844bd81f      e83cfeffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x5606844bd824      898554ffffff   mov dword [var_ach], eax
│           0x5606844bd82a      488b4d90       mov rcx, qword [var_70h]
│           0x5606844bd82e      488d9558ffff.  lea rdx, [var_a8h]
│           0x5606844bd835      8bb550ffffff   mov esi, dword [var_b0h]
│           0x5606844bd83b      8b8554ffffff   mov eax, dword [var_ach]
│           0x5606844bd841      89c7           mov edi, eax
│           0x5606844bd843      b800000000     mov eax, 0
│           0x5606844bd848      e803feffff     call sym.imp.sendfile
│           0x5606844bd84d      8b8554ffffff   mov eax, dword [var_ach]
│           0x5606844bd853      89c7           mov edi, eax
│           0x5606844bd855      b800000000     mov eax, 0
│           0x5606844bd85a      e8d1fdffff     call sym.imp.close      ; int close(int fildes)
│           0x5606844bd85f      8b8550ffffff   mov eax, dword [var_b0h]
│           0x5606844bd865      89c7           mov edi, eax
│           0x5606844bd867      b800000000     mov eax, 0
│           0x5606844bd86c      e8bffdffff     call sym.imp.close      ; int close(int fildes)
│           0x5606844bd871      b800000000     mov eax, 0
│           0x5606844bd876      488b4df8       mov rcx, qword [var_8h]
│           0x5606844bd87a      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x5606844bd883      7405           je 0x5606844bd88a
│       │   0x5606844bd885      e896fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x5606844bd88a      c9             leave
└           0x5606844bd88b      c3             ret
[0x5606844bd78a]> 
```
First of all, we identify a call to fstat or file status. This call obtains the information related to a file, such as path, permissions and so (https://linux.die.net/man/2/fstat)
```
│           0x5606844bd7dc      898550ffffff   mov dword [var_b0h], eax
│           0x5606844bd7e2      488d9560ffff.  lea rdx, [var_a0h]
│           0x5606844bd7e9      8b8550ffffff   mov eax, dword [var_b0h]
│           0x5606844bd7ef      4889d6         mov rsi, rdx
│           0x5606844bd7f2      89c7           mov edi, eax
│           0x5606844bd7f4      b800000000     mov eax, 0
│           0x5606844bd7f9      e812010000     call sym.fstat          ; int fstat(int fildes, void *buf)
│           0x5606844bd7fe      8b9578ffffff   mov edx, dword [var_88h]
```
The information returned by fstat is stored inside a struct in memory, so as we can see a pointer to that struct is being passed as one of the parameters. Note that this technique is very common when dealing with system code, as functions in C do not return objects it is prettty common that when we need to recover some structured information we send a pointer to the corresponding struct to the function and the function then "fills" that struct.
```
struct stat {
    dev_t     st_dev;     /* ID of device containing file */
    ino_t     st_ino;     /* inode number */
    mode_t    st_mode;    /* protection */
    nlink_t   st_nlink;   /* number of hard links */
    uid_t     st_uid;     /* user ID of owner */
    gid_t     st_gid;     /* group ID of owner */
    dev_t     st_rdev;    /* device ID (if special file) */
    off_t     st_size;    /* total size, in bytes */
    blksize_t st_blksize; /* blocksize for file system I/O */
    blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
    time_t    st_atime;   /* time of last access */
    time_t    st_mtime;   /* time of last modification */
    time_t    st_ctime;   /* time of last status change */
};
```
As we can see, after the call, the space has been filled in memory, we can, for example identify the 0xB = 11 dec corresponding to the off_t field
```
[0x5606844bd7fe]> pxw @ 0x7fff922b2700
0x7fff922b2700  0x0000fd01 0x00000000 0x00225848 0x00000000  ........HX".....
0x7fff922b2710  0x00000001 0x00000000 0x000081a4 0x000003e8  ................
0x7fff922b2720  0x000003e8 0x00000000 0x00000000 0x00000000  ................
0x7fff922b2730  0x0000000b 0x00000000 0x00001000 0x00000000  ................
0x7fff922b2740  0x00000008 0x00000000 0x5ec14670 0x00000000  ........pF.^....
0x7fff922b2750  0x144d8dec 0x00000000 0x5ec06dfa 0x00000000  ..M......m.^....
```
We also see that r2 does not recognize the struct (as usual) it uses independent variable references for each value, that correspond to the struct size.

#### Structs to files
What if the program needs to save its state somehow? Some programs make use of custom files to save some useful information on disk. Think about a program like this:
```c
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <fcntl.h>
#include <stdlib.h>

  struct person  
{ 
    int id; 
    char fname[20]; 
    char lname[20]; 
}; 
  
int main () 
{ 
    int outfile;
      
    outfile = open ("person.dat", O_WRONLY | O_CREAT, 0644); 

    if(outfile > 0){
  
    struct person input1 = {1, "artik", "blue"}; 

    struct person input2 = {2, "john", "doe"}; 
      
    write (outfile , &input2, sizeof(struct person)); 
    write (outfile , &input1, sizeof(struct person)); 
  
    close(outfile); 

    }
  
    return 0; 
} 
```
The program is literally dumpìng a struct to disk, that's interesting let's see how it's done:
```
[0x55f0d1e2e73a]> pdf
            ; DATA XREF from entry0 @ 0x55f0d1e2e64d
┌ 272: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_74h @ rbp-0x74
│           ; var int64_t var_70h @ rbp-0x70
│           ; var int64_t var_6ch @ rbp-0x6c
│           ; var int64_t var_64h @ rbp-0x64
│           ; var int64_t var_5ch @ rbp-0x5c
│           ; var int64_t var_58h @ rbp-0x58
│           ; var int64_t var_50h @ rbp-0x50
│           ; var int64_t var_48h @ rbp-0x48
│           ; var int64_t var_40h @ rbp-0x40
│           ; var int64_t var_3ch @ rbp-0x3c
│           ; var int64_t var_34h @ rbp-0x34
│           ; var int64_t var_2ch @ rbp-0x2c
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_8h @ rbp-0x8
│           0x55f0d1e2e73a      55             push rbp
│           0x55f0d1e2e73b      4889e5         mov rbp, rsp
│           0x55f0d1e2e73e      4883c480       add rsp, 0xffffffffffffff80
│           0x55f0d1e2e742      64488b042528.  mov rax, qword fs:[0x28]
│           0x55f0d1e2e74b      488945f8       mov qword [var_8h], rax
│           0x55f0d1e2e74f      31c0           xor eax, eax
│           0x55f0d1e2e751      baa4010000     mov edx, 0x1a4          ; 420
│           0x55f0d1e2e756      be41000000     mov esi, 0x41           ; 'A' ; 65
│           0x55f0d1e2e75b      488d3d720100.  lea rdi, str.person.dat ; 0x55f0d1e2e8d4 ; "person.dat"
│           0x55f0d1e2e762      b800000000     mov eax, 0
│           0x55f0d1e2e767      e8a4feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x55f0d1e2e76c      89458c         mov dword [var_74h], eax
│           0x55f0d1e2e76f      837d8c00       cmp dword [var_74h], 0
│       ┌─< 0x55f0d1e2e773      0f8eb6000000   jle 0x55f0d1e2e82f
│       │   0x55f0d1e2e779      c74590010000.  mov dword [var_70h], 1
│       │   0x55f0d1e2e780      48b861727469.  movabs rax, 0x6b69747261 ; 'artik'
│       │   0x55f0d1e2e78a      ba00000000     mov edx, 0
│       │   0x55f0d1e2e78f      48894594       mov qword [var_6ch], rax
│       │   0x55f0d1e2e793      4889559c       mov qword [var_64h], rdx
│       │   0x55f0d1e2e797      c745a4000000.  mov dword [var_5ch], 0
│       │   0x55f0d1e2e79e      48c745a8626c.  mov qword [var_58h], 0x65756c62 ; 'blue'
│       │   0x55f0d1e2e7a6      48c745b00000.  mov qword [var_50h], 0
│       │   0x55f0d1e2e7ae      c745b8000000.  mov dword [var_48h], 0
│       │   0x55f0d1e2e7b5      c745c0020000.  mov dword [var_40h], 2
│       │   0x55f0d1e2e7bc      48c745c46a6f.  mov qword [var_3ch], 0x6e686f6a ; 'john'
│       │   0x55f0d1e2e7c4      48c745cc0000.  mov qword [var_34h], 0
│       │   0x55f0d1e2e7cc      c745d4000000.  mov dword [var_2ch], 0
│       │   0x55f0d1e2e7d3      48c745d8646f.  mov qword [var_28h], 0x656f64 ; 'doe'
│       │   0x55f0d1e2e7db      48c745e00000.  mov qword [var_20h], 0
│       │   0x55f0d1e2e7e3      c745e8000000.  mov dword [var_18h], 0
│       │   0x55f0d1e2e7ea      488d4dc0       lea rcx, [var_40h]
│       │   0x55f0d1e2e7ee      8b458c         mov eax, dword [var_74h]
│       │   0x55f0d1e2e7f1      ba2c000000     mov edx, 0x2c           ; ',' ; 44
│       │   0x55f0d1e2e7f6      4889ce         mov rsi, rcx
│       │   0x55f0d1e2e7f9      89c7           mov edi, eax
│       │   0x55f0d1e2e7fb      b800000000     mov eax, 0
│       │   0x55f0d1e2e800      e8dbfdffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│       │   0x55f0d1e2e805      488d4d90       lea rcx, [var_70h]
│       │   0x55f0d1e2e809      8b458c         mov eax, dword [var_74h]
│       │   0x55f0d1e2e80c      ba2c000000     mov edx, 0x2c           ; ',' ; 44
│       │   0x55f0d1e2e811      4889ce         mov rsi, rcx
│       │   0x55f0d1e2e814      89c7           mov edi, eax
│       │   0x55f0d1e2e816      b800000000     mov eax, 0
│       │   0x55f0d1e2e81b      e8c0fdffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│       │   0x55f0d1e2e820      8b458c         mov eax, dword [var_74h]
│       │   0x55f0d1e2e823      89c7           mov edi, eax
│       │   0x55f0d1e2e825      b800000000     mov eax, 0
│       │   0x55f0d1e2e82a      e8d1fdffff     call sym.imp.close      ; int close(int fildes)
│       └─> 0x55f0d1e2e82f      b800000000     mov eax, 0
│           0x55f0d1e2e834      488b75f8       mov rsi, qword [var_8h]
│           0x55f0d1e2e838      644833342528.  xor rsi, qword fs:[0x28]
│       ┌─< 0x55f0d1e2e841      7405           je 0x55f0d1e2e848
│       │   0x55f0d1e2e843      e8a8fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55f0d1e2e848      c9             leave
└           0x55f0d1e2e849      c3             ret
[0x55f0d1e2e73a]> 
```
So as usual it does not recognize the struct keeping a reference for each val:
```
│       │   0x55f0d1e2e779      c74590010000.  mov dword [var_70h], 1
│       │   0x55f0d1e2e780      48b861727469.  movabs rax, 0x6b69747261 ; 'artik'
│       │   0x55f0d1e2e78a      ba00000000     mov edx, 0
│       │   0x55f0d1e2e78f      48894594       mov qword [var_6ch], rax
│       │   0x55f0d1e2e793      4889559c       mov qword [var_64h], rdx
│       │   0x55f0d1e2e797      c745a4000000.  mov dword [var_5ch], 0
│       │   0x55f0d1e2e79e      48c745a8626c.  mov qword [var_58h], 0x65756c62 ; 'blue'
│       │   0x55f0d1e2e7a6      48c745b00000.  mov qword [var_50h], 0
│       │   0x55f0d1e2e7ae      c745b8000000.  mov dword [var_48h], 0
│       │   0x55f0d1e2e7b5      c745c0020000.  mov dword [var_40h], 2
│       │   0x55f0d1e2e7bc      48c745c46a6f.  mov qword [var_3ch], 0x6e686f6a ; 'john'
│       │   0x55f0d1e2e7c4      48c745cc0000.  mov qword [var_34h], 0
│       │   0x55f0d1e2e7cc      c745d4000000.  mov dword [var_2ch], 0
│       │   0x55f0d1e2e7d3      48c745d8646f.  mov qword [var_28h], 0x656f64 ; 'doe'
│       │   0x55f0d1e2e7db      48c745e00000.  mov qword [var_20h], 0
│       │   0x55f0d1e2e7e3      c745e8000000.  mov dword [var_18h], 0
```
As you see it will create an initialize those structs and fill the blanks with zeroes.
```
│       │   0x55f0d1e2e7fb      b800000000     mov eax, 0
│       │   0x55f0d1e2e800      e8dbfdffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│       │   0x55f0d1e2e805      488d4d90       lea rcx, [var_70h]
│       │   ;-- rip:
│       │   0x55f0d1e2e809 b    8b458c         mov eax, dword [var_74h]
```
Then it just writes the content to disk, let's inspect what gets sent to the file:
```
[0x55f0d1e2e809]> pxw @ 0x7ffdb5e2bf3c
0x7ffdb5e2bf3c  0x00000003 0x00000001 0x69747261 0x0000006b  ........artik...
0x7ffdb5e2bf4c  0x00000000 0x00000000 0x00000000 0x65756c62  ............blue
0x7ffdb5e2bf5c  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffdb5e2bf6c  0x00000000 0x00000002 0x6e686f6a 0x00000000  ........john....
0x7ffdb5e2bf7c  0x00000000 0x00000000 0x00000000 0x00656f64  ............doe.
```
So, the struct, mapped in memory gets "literally" dumpted to the file
```
[0x55f0d1e2e809]> "td struct person  {   long id;  char fname[20];  char lname[20]; }; "
[0x55f0d1e2e809]> tp person @ 0x7ffdb5e2bf3c
    id : 0x7ffdb5e2bf3c = (qword)0x0000000100000003
 fname : 0x7ffdb5e2bf44 = "artik"
 lname : 0x7ffdb5e2bf58 = "blue"
```

#### Moving inside the file
What if we want to initially jump straight to a specific value? If we want to do that instead of have to parse the full file (imagine a long file with known format) we can use lseek. With lseek we can move forward and backwards inside the file.

Look at this:
```c
#include <stdio.h> 
#include <stdlib.h> 
#include <fcntl.h>
#include <stdlib.h>
struct person  
{ 
    int id; 
    char fname[20]; 
    char lname[20]; 
}; 


int main () 
{ 
    int infile, outfile; 
    struct person input; 
      
    infile = open ("person.dat", O_RDONLY , 0644); 
    lseek(infile, 1*sizeof(struct person), SEEK_CUR);
    read(infile, &input, sizeof(struct person));

    printf("second person val = %d, %s, %s \n", input.id, input.fname, input.lname);
 
    close (infile); 
  
    return 0; 
} 
```
The presented code opens the file for reading and uses lseek to tell the kernel to move inside the file. Doing one times the sizeof the struct means moving one position away from the first value, so, moving right to the second value.

The file that gets loaded looks like this:
```
[0x00000000]> x
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00000000  0200 0000 6a6f 686e 0000 0000 0000 0000  ....john........
0x00000010  0000 0000 0000 0000 646f 6500 0000 0000  ........doe.....
0x00000020  0000 0000 0000 0000 0000 0000 0100 0000  ................
0x00000030  6172 7469 6b00 0000 0000 0000 0000 0000  artik...........
0x00000040  0000 0000 626c 7565 0000 0000 0000 0000  ....blue........
0x00000050  0000 0000 0000 0000 ffff ffff ffff ffff  ................



[0x00000000]> izz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000004 0x00000004 4   5            ascii john
1   0x00000030 0x00000030 5   6            ascii artik
2   0x00000044 0x00000044 4   5            ascii blue

[0x00000000]> 
```

We can easily edit the file to write new content ourselves with wx

```
[0x00000000]> wz red @ 0x00000018
[0x00000000]> x
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00000000  0200 0000 6a6f 686e 0000 0000 0000 0000  ....john........
0x00000010  0000 0000 0000 0000 7265 6400 0000 0000  ........red.....
0x00000020  0000 0000 0000 0000 0000 0000 0100 0000  ................
0x00000030  6172 7469 6b00 0000 0000 0000 0000 0000  artik...........
0x00000040  0000 0000 626c 7565 0000 0000 0000 0000  ....blue........
0x00000050  0000 0000 0000 0000 ffff ffff ffff ffff  ................
```
As you can see, and this is important to remark, the previously generated file that now gets loaded back in memory is a data file, so hex content not an ascii file, if you are going to edit it, you'll have to use an hex editor or you may "break" the file. This one is very simple though, it just contains those values located at very specific positions and the rest is just filled with zeores, some files have very specific formats that include bytes at certain positions (like the MZ signature on Windows programs), we'll talk about that later on on this course.
#### File loading and XOR string encoding
The following program reads from the file, loads those values back inside a struct, then encrypts them and dumps the result to another file. The goal of this simple program is just to show that data management operations such as the ones presented can be easily done and by the way are commonly done by many programs, including malware (in a bit more advanced way), the logic is the same, let's see:
```c
#include <stdio.h> 
#include <stdlib.h> 
#include <fcntl.h>
#include <stdlib.h>
struct person  
{ 
    int id; 
    char fname[20]; 
    char lname[20]; 
}; 


void cryp(char  arr[]){
    char k[20] = "01234567890123456789";
    for(int i = 0; i < sizeof(arr); i ++){
        arr[i] ^= k[i];
    }
    arr[sizeof(arr)-1]='\0';

}
int main () 
{ 
    int infile, outfile; 
    struct person input; 
      
    infile = open ("person.dat", O_RDONLY , 0644); 
    outfile = open ("person.cry", O_WRONLY | O_CREAT, 0644);
    while(read(infile, &input, sizeof(struct person))){ 
        cryp(input.fname);
        cryp(input.lname);

        write(outfile, &input, sizeof(struct person));
    }
    close (infile); 
  
    return 0; 
} 
```
We jump straight to r2:
```
[0x7fb0c4197090]> s main
[0x55de52c0c82c]> pdf
            ; DATA XREF from entry0 @ 0x55de52c0c69d
┌ 217: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_48h @ rbp-0x48
│           ; var int64_t var_44h @ rbp-0x44
│           ; var int64_t var_40h @ rbp-0x40
│           ; var int64_t var_8h @ rbp-0x8
│           0x55de52c0c82c      55             push rbp
│           0x55de52c0c82d      4889e5         mov rbp, rsp
│           0x55de52c0c830      4883ec50       sub rsp, 0x50
│           0x55de52c0c834      64488b042528.  mov rax, qword fs:[0x28]
│           0x55de52c0c83d      488945f8       mov qword [var_8h], rax
│           0x55de52c0c841      31c0           xor eax, eax
│           0x55de52c0c843      baa4010000     mov edx, 0x1a4          ; 420
│           0x55de52c0c848      be00000000     mov esi, 0
│           0x55de52c0c84d      488d3d400100.  lea rdi, str.person.dat ; 0x55de52c0c994 ; "person.dat"
│           0x55de52c0c854      b800000000     mov eax, 0
│           0x55de52c0c859      e802feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x55de52c0c85e      8945b8         mov dword [var_48h], eax
│           0x55de52c0c861      baa4010000     mov edx, 0x1a4          ; 420
│           0x55de52c0c866      be41000000     mov esi, 0x41           ; 'A' ; 65
│           0x55de52c0c86b      488d3d2d0100.  lea rdi, str.person.cry ; 0x55de52c0c99f ; "person.cry"
│           0x55de52c0c872      b800000000     mov eax, 0
│           0x55de52c0c877      e8e4fdffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x55de52c0c87c      8945bc         mov dword [var_44h], eax
│       ┌─< 0x55de52c0c87f      eb3b           jmp 0x55de52c0c8bc
│      ┌──> 0x55de52c0c881      488d45c0       lea rax, [var_40h]
│      ╎│   0x55de52c0c885      4883c004       add rax, 4
│      ╎│   0x55de52c0c889      4889c7         mov rdi, rax
│      ╎│   0x55de52c0c88c      e8f9feffff     call sym.cryp
│      ╎│   0x55de52c0c891      488d45c0       lea rax, [var_40h]
│      ╎│   0x55de52c0c895      4883c018       add rax, 0x18           ; 24
│      ╎│   0x55de52c0c899      4889c7         mov rdi, rax
│      ╎│   0x55de52c0c89c      e8e9feffff     call sym.cryp
│      ╎│   0x55de52c0c8a1      488d4dc0       lea rcx, [var_40h]
│      ╎│   0x55de52c0c8a5      8b45bc         mov eax, dword [var_44h]
│      ╎│   0x55de52c0c8a8      ba2c000000     mov edx, 0x2c           ; ',' ; 44
│      ╎│   0x55de52c0c8ad      4889ce         mov rsi, rcx
│      ╎│   0x55de52c0c8b0      89c7           mov edi, eax
│      ╎│   0x55de52c0c8b2      b800000000     mov eax, 0
│      ╎│   0x55de52c0c8b7      e864fdffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│      ╎│   ; CODE XREF from main @ 0x55de52c0c87f
│      ╎└─> 0x55de52c0c8bc      488d4dc0       lea rcx, [var_40h]
│      ╎    0x55de52c0c8c0      8b45b8         mov eax, dword [var_48h]
│      ╎    0x55de52c0c8c3      ba2c000000     mov edx, 0x2c           ; ',' ; 44
│      ╎    0x55de52c0c8c8      4889ce         mov rsi, rcx
│      ╎    0x55de52c0c8cb      89c7           mov edi, eax
│      ╎    0x55de52c0c8cd      b800000000     mov eax, 0
│      ╎    0x55de52c0c8d2      e879fdffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
│      ╎    0x55de52c0c8d7      85c0           test eax, eax
│      └──< 0x55de52c0c8d9      75a6           jne 0x55de52c0c881
│           0x55de52c0c8db      8b45b8         mov eax, dword [var_48h]
│           0x55de52c0c8de      89c7           mov edi, eax
│           0x55de52c0c8e0      b800000000     mov eax, 0
│           0x55de52c0c8e5      e856fdffff     call sym.imp.close      ; int close(int fildes)
│           0x55de52c0c8ea      b800000000     mov eax, 0
│           0x55de52c0c8ef      488b55f8       mov rdx, qword [var_8h]
│           0x55de52c0c8f3      644833142528.  xor rdx, qword fs:[0x28]
│       ┌─< 0x55de52c0c8fc      7405           je 0x55de52c0c903
│       │   0x55de52c0c8fe      e82dfdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55de52c0c903      c9             leave
└           0x55de52c0c904      c3             ret
[0x55de52c0c82c]> 
```
We can start by the first function, the main, and we can jump straight after the first open:

```
│                                                                      ; 0x55de52c0c994 ; "person.dat"
│           0x55de52c0c854      b800000000     mov eax, 0
│           0x55de52c0c859      e802feffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           ;-- rip:
│           0x55de52c0c85e b    8945b8         mov dword [var_48h], eax
│           0x55de52c0c861      baa4010000     mov edx, 0x1a4          ; 420
```
The first open launches and opens person.dat, so it returns the corresponding file descriptor. In radare2 we can list the file descriptors opened by the program by doing dd:
```
[0x55de52c0c85e]> dd
0 0x0 r-C /dev/pts/2
1 0x0 r-C /dev/pts/2
2 0x0 r-C /dev/pts/2
3 0x0 r-S /home/red/c/part2/new/person.dat
```
As you see, 0-3 fd's are always open. Then after the second open()
```
│           ;-- rip:
│           0x55de52c0c87c b    8945bc         mov dword [var_44h], eax
│       ┌─< 0x55de52c0c87f      eb3b           jmp 0x55de52c0c8bc
│      ┌──> 0x55de52c0c881      488d45c0       lea rax, [var_40h]
│      ╎│   0x55de52c0c885      4883c004       add rax, 4
```
The program now handles two files, the fd number 4 has been added:
```
[0x55de52c0c87c]> dd
0 0x0 r-C /dev/pts/2
1 0x0 r-C /dev/pts/2
2 0x0 r-C /dev/pts/2
3 0x0 r-S /home/red/c/part2/new/person.dat
4 0x0 r-S /home/red/c/part2/new/person.cry
```
Then the program goes chunk by chunk on the file, loads into the struct and sends a reference to those fields to the crypt function:
```
│           0x55de52c0c87c b    8945bc         mov dword [var_44h], eax
│       ┌─< 0x55de52c0c87f      eb3b           jmp 0x55de52c0c8bc
│      ┌──> 0x55de52c0c881      488d45c0       lea rax, [var_40h]
│      ╎│   ;-- rip:
│      ╎│   0x55de52c0c885 b    4883c004       add rax, 4
│      ╎│   0x55de52c0c889      4889c7         mov rdi, rax
│      ╎│   0x55de52c0c88c      e8f9feffff     call sym.cryp
│      ╎│   0x55de52c0c891      488d45c0       lea rax, [var_40h]
│      ╎│   0x55de52c0c895      4883c018       add rax, 0x18           ; 24
│      ╎│   0x55de52c0c899      4889c7         mov rdi, rax
│      ╎│   0x55de52c0c89c      e8e9feffff     call sym.cryp
```
We can inspect those values before entering the crypt function:
```
[0x557979560885]> afvd
var var_8h = 0x7ffc1c931058 = (qword)0xdb75146eaecef500
var var_48h = 0x7ffc1c931018 = (qword)0x0000000400000003
var var_44h = 0x7ffc1c93101c = (qword)0x0000000200000004
var var_40h = 0x7ffc1c931020 = (qword)0x6e686f6a00000002
[0x557979560885]> pxw @ 0x7ffc1c931020
0x7ffc1c931020  0x00000002 0x6e686f6a 0x00000000 0x00000000  ....john........
0x7ffc1c931030  0x00000000 0x00000000 0x00646572 0x00000000  ........red.....
0x7ffc1c931040  0x00000000 0x00000000 0x00000000 0x00005579  ............yU..
0x7ffc1c931050  0x1c931140 0x00007ffc 0xaecef500 0xdb75146e  @...........n.u.
0x7ffc1c931060  0x79560910 0x00005579 0xd4fb9b97 0x00007f20  ..VyyU...... ...
```
Then we have the crypt function right here:
```
[0x557979560885]> db sym.cryp
[0x557979560885]> dc
hit breakpoint at: 55797956078a
[0x55797956078a]> pdf
            ; CALL XREFS from main @ 0x55797956088c, 0x55797956089c
            ;-- rip:
┌ 162: sym.cryp (int64_t arg1);
│           ; var int64_t var_38h @ rbp-0x38
│           ; var int64_t var_24h @ rbp-0x24
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int64_t arg1 @ rdi
│           0x55797956078a b    55             push rbp
│           0x55797956078b      4889e5         mov rbp, rsp
│           0x55797956078e      4883ec40       sub rsp, 0x40
│           0x557979560792      48897dc8       mov qword [var_38h], rdi ; arg1
│           0x557979560796      64488b042528.  mov rax, qword fs:[0x28]
│           0x55797956079f      488945f8       mov qword [var_8h], rax
│           0x5579795607a3      31c0           xor eax, eax
│           0x5579795607a5      48b830313233.  movabs rax, 0x3736353433323130 ; '01234567'
│           0x5579795607af      48ba38393031.  movabs rdx, 0x3534333231303938 ; '89012345'
│           0x5579795607b9      488945e0       mov qword [var_20h], rax
│           0x5579795607bd      488955e8       mov qword [var_18h], rdx
│           0x5579795607c1      c745f0363738.  mov dword [var_10h], 0x39383736 ; '6789'
│           0x5579795607c8      c745dc000000.  mov dword [var_24h], 0
│       ┌─< 0x5579795607cf      eb31           jmp 0x557979560802
│      ┌──> 0x5579795607d1      8b45dc         mov eax, dword [var_24h]
│      ╎│   0x5579795607d4      4863d0         movsxd rdx, eax
│      ╎│   0x5579795607d7      488b45c8       mov rax, qword [var_38h]
│      ╎│   0x5579795607db      4801d0         add rax, rdx
│      ╎│   0x5579795607de      0fb630         movzx esi, byte [rax]
│      ╎│   0x5579795607e1      8b45dc         mov eax, dword [var_24h]
│      ╎│   0x5579795607e4      4898           cdqe
│      ╎│   0x5579795607e6      0fb64c05e0     movzx ecx, byte [rbp + rax - 0x20]
│      ╎│   0x5579795607eb      8b45dc         mov eax, dword [var_24h]
│      ╎│   0x5579795607ee      4863d0         movsxd rdx, eax
│      ╎│   0x5579795607f1      488b45c8       mov rax, qword [var_38h]
│      ╎│   0x5579795607f5      4801d0         add rax, rdx
│      ╎│   0x5579795607f8      31ce           xor esi, ecx
│      ╎│   0x5579795607fa      89f2           mov edx, esi
│      ╎│   0x5579795607fc      8810           mov byte [rax], dl
│      ╎│   0x5579795607fe      8345dc01       add dword [var_24h], 1
│      ╎│   ; CODE XREF from sym.cryp @ 0x5579795607cf
│      ╎└─> 0x557979560802      8b45dc         mov eax, dword [var_24h]
│      ╎    0x557979560805      83f807         cmp eax, 7              ; 7
│      └──< 0x557979560808      76c7           jbe 0x5579795607d1
│           0x55797956080a      488b45c8       mov rax, qword [var_38h]
│           0x55797956080e      4883c007       add rax, 7
│           0x557979560812      c60000         mov byte [rax], 0
│           0x557979560815      90             nop
│           0x557979560816      488b45f8       mov rax, qword [var_8h]
│           0x55797956081a      644833042528.  xor rax, qword fs:[0x28]
│       ┌─< 0x557979560823      7405           je 0x55797956082a
│       │   0x557979560825      e806feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55797956082a      c9             leave
└           0x55797956082b      c3             ret
[0x55797956078a]> 
```
And XOR is being done like this:
```
│      ╎│   0x5579795607f1      488b45c8       mov rax, qword [var_38h]
│      ╎│   0x5579795607f5      4801d0         add rax, rdx
│      ╎│   0x5579795607f8      31ce           xor esi, ecx
│      ╎│   0x5579795607fa      89f2           mov edx, esi
│      ╎│   0x5579795607fc      8810           mov byte [rax], dl
│      ╎│   0x5579795607fe      8345dc01       add dword [var_24h], 1
```
With the following key that gets loaded before doing XOR:
```
[0x5579795607fa]> pxw @ 0x7ffc1c930fc8
0x7ffc1c930fc8  0x1c931024 0x00007ffc 0x1c9892a8 0x00007ffc  $...............
0x7ffc1c930fd8  0xd55b2710 0x00000001 0x33323130 0x37363534  .'[.....01234567
0x7ffc1c930fe8  0x31303938 0x35343332 0x39383736 0x00000000  890123456789....
```
Then encryption is done char by char as you see here:
```
[0x5579795607f8]> dr esi
0x0000006f
[0x5579795607f8]> dr ecx
0x00000031 (= ascii l from blue)
[0x5579795607f8]> 
[0x5579795607f8]> ds
[0x5579795607fa]> dr esi
0x0000005e

[0x5579795607fa]> dr rax
0x7ffc1c931025
[0x5579795607fa]> pxw @ 0x7ffc1c931024
0x7ffc1c931024  0x6e686f5a 0x00000000 0x00000000 0x00000000  Zohn............
0x7ffc1c931034  0x00000000 0x00646572 0x00000000 0x00000000  ....red.........
```
When dealing with really long and complex functions that return a value, you may want to set a breakpoint before and after their execution and just figure out about the internals...

Sometimes you may be doing static analysis on a program you cannot run, in such cases dealing with encryption routines can crack your balls, ESIL comes handly
#### A few words on ESIL

No, we are not talking about some middle east terrorist organization. ESIL stands for 'Evaluable Strings Intermediate Language' and basically, it helps us in debugging programs without actually having to run it on our machines. I'm going to be very brief on this topic as we'll explore it more along the course. 


Let's start with this example:

```
#include <stdio.h>


void main(){

        char a[4] = "abcd";
        char b[4] = "XYZU";


        for (int i=0; i < 4; i++){

                b[i] ^= a[i];
        }

        printf("%s \n",b);
}
```
On general terms: there will be ocasions when we don't want or we just cannot run the program on our machine. That may happen when dealing with malware or when reversing programs that correspond to other weird architectures (such as gameboy), on those ocasions static analysis is not enough as we may need to calculate where the code will jump based on a specific input, or we may need to go over a specific encryption routine that can be very hard/time consuming to analyse "by hand". 

Esil helps with this, r2 offers the ESIL VM, read about it here: https://radare.gitbooks.io/radare2book/analysis/emulation.html

Along with the help of that VM we can debug the program without actually running it, the stuff we'll be able to do is limited, as we are just emulating and we are not backed by the os, we won't be able to debug syscalls such as the ones we just saw. Eventhough ESIL will be able for calculations.

We enable it like this:
```
[0x000005a0]> s main
[0x000005a0]> e asm.esil = true
[0x000005a0]> aei
[0x000005a0]> aeim
[0x000005a0]> aeip
```

```
[0x000006aa]> pdf
            ; DATA XREF from entry0 @ 0x5bd
            ;-- rip:
┌ 134: int main (int argc, char **argv, char **envp);
│           ; var signed int64_t var_14h @ rbp-0x14
│           ; var int64_t var_10h @ rbp-0x10
│           ; var char *var_ch @ rbp-0xc
│           ; var int64_t canary @ rbp-0x8
│           0x000006aa      55             rbp,8,rsp,-,=[8],8,rsp,-=
│           0x000006ab      4889e5         rsp,rbp,=
│           0x000006ae      4883ec20       32,rsp,-=,63,$o,of,:=,63,$s,sf,:=,$z,zf,:=,$p,pf,:=,64,$b,cf,:=
│           0x000006b2      64488b042528.  0x28,[8],rax,=
│           0x000006bb      488945f8       rax,0x8,rbp,-,=[8]
│           0x000006bf      31c0           eax,rax,^,0xffffffff,&,rax,=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:=
│           0x000006c1      c745f0616263.  1684234849,0x10,rbp,-,=[4]  ; 'abcd'
│                                                                      ; 0x64636261
│           0x000006c8      c745f458595a.  1431984472,0xc,rbp,-,=[4]   ; 'XYZU'
│                                                                      ; 0x555a5958
│           0x000006cf      c745ec000000.  0,0x14,rbp,-,=[4]
│       ┌─< 0x000006d6      eb23           0x6fb,rip,=
│       │   ; CODE XREF from main @ 0x6ff
│      ┌──> 0x000006d8      8b45ec         0x14,rbp,-,[4],rax,=
│      ╎│   0x000006db      4898           eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}
│      ╎│   0x000006dd      0fb65405f4     0xc,rax,rbp,+,-,[1],rdx,=
│      ╎│   0x000006e2      8b45ec         0x14,rbp,-,[4],rax,=
│      ╎│   0x000006e5      4898           eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}
│      ╎│   0x000006e7      0fb64405f0     0x10,rax,rbp,+,-,[1],rax,=
│      ╎│   0x000006ec      31c2           eax,rdx,^,0xffffffff,&,rdx,=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:=
│      ╎│   0x000006ee      8b45ec         0x14,rbp,-,[4],rax,=
│      ╎│   0x000006f1      4898           eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}
│      ╎│   0x000006f3      885405f4       dl,0xc,rax,rbp,+,-,=[1]
│      ╎│   0x000006f7      8345ec01       1,0x14,rbp,-,+=[4],31,$o,of,:=,31,$s,sf,:=,$z,zf,:=,31,$c,cf,:=,$p,pf,:=
│      ╎│   ; CODE XREF from main @ 0x6d6
│      ╎└─> 0x000006fb      837dec03       3,0x14,rbp,-,[4],==,$z,zf,:=,32,$b,cf,:=,$p,pf,:=,31,$s,sf,:=,31,$o,of,:=
│      └──< 0x000006ff      7ed7           of,sf,^,zf,|,?{,1752,rip,=,}
│           0x00000701      488d45f4       0xc,rbp,-,rax,=
│           0x00000705      4889c6         rax,rsi,=
│           0x00000708      488d3da50000.  0xa5,rip,+,rdi,=            ; str.s
│                                                                      ; 0x7b4 ; "%s \n" ; const char *format
│           0x0000070f      b800000000     0,rax,=
│           0x00000714      e867feffff     1408,rip,8,rsp,-=,rsp,=[],rip,= ; sym.imp.printf ; int printf(const char *format)
│           0x00000719      90             ,
│           0x0000071a      488b45f8       0x8,rbp,-,[8],rax,=
│           0x0000071e      644833042528.  0x28,[8],rax,^=,$z,zf,:=,$p,pf,:=,63,$s,sf,:=,0,cf,:=,0,of,:=
│       ┌─< 0x00000727      7405           zf,?{,1838,rip,=,}
│       │   0x00000729      e842feffff     1392,rip,8,rsp,-=,rsp,=[],rip,= ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x727
│       └─> 0x0000072e      c9             rbp,rsp,=,rsp,[8],rbp,=,8,rsp,+=
└           0x0000072f      c3             rsp,[8],rip,=,8,rsp,+=
```
As you see, after getting into ESIL instructions appear on its format, you can find the instruction set here: https://radare.gitbooks.io/radare2book/disassembling/esil.html


Inside esil we can do aesu to emulate the execution untill a specific mem addr is reached:

For example, in our program we can inspect the byte per byte XOR inside the loop with ESIL like this:

```
[0x000006aa]> aesu 0x000006ee
[0x000006d8]> dr
rax = 0x00000061
rbx = 0x00000000
rcx = 0x00000000
rdx = 0x00000039
```
Here you can see that the operation has been computed and ESIL registers have been updated (watch those ascii codes)

In our case we can also "jump" after the encryption is done and inspect the result like this:
```
[0x000006aa]> aesu 0x00000701

[0x000006d8]> pdf
            ; DATA XREF from entry0 @ 0x5bd
┌ 134: int main (int argc, char **argv, char **envp);
│           ; var signed int64_t var_14h @ rbp-0x14
│           ; var int64_t var_10h @ rbp-0x10
│           ; var char *var_ch @ rbp-0xc
│           ; var int64_t canary @ rbp-0x8
│           0x000006aa      55             rbp,8,rsp,-,=[8],8,rsp,-=
│           0x000006ab      4889e5         rsp,rbp,=
│           0x000006ae      4883ec20       32,rsp,-=,63,$o,of,:=,63,$s,sf,:=,$z,zf,:=,$p,pf,:=,64,$b,cf,:=
│           0x000006b2      64488b042528.  0x28,[8],rax,=
│           0x000006bb      488945f8       rax,0x8,rbp,-,=[8]
│           0x000006bf      31c0           eax,rax,^,0xffffffff,&,rax,=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:=
│           0x000006c1      c745f0616263.  1684234849,0x10,rbp,-,=[4]  ; 'abcd'
│                                                                      ; 0x64636261
│           0x000006c8      c745f458595a.  1431984472,0xc,rbp,-,=[4]   ; 'XYZU'
│                                                                      ; 0x555a5958
│           0x000006cf      c745ec000000.  0,0x14,rbp,-,=[4]
│       ┌─< 0x000006d6      eb23           0x6fb,rip,=
│       │   ; CODE XREF from main @ 0x6ff
│      ┌──> 0x000006d8      8b45ec         0x14,rbp,-,[4],rax,=
│      ╎│   0x000006db      4898           eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}
│      ╎│   0x000006dd      0fb65405f4     0xc,rax,rbp,+,-,[1],rdx,=
│      ╎│   0x000006e2      8b45ec         0x14,rbp,-,[4],rax,=
│      ╎│   0x000006e5      4898           eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}
│      ╎│   0x000006e7      0fb64405f0     0x10,rax,rbp,+,-,[1],rax,=
│      ╎│   0x000006ec      31c2           eax,rdx,^,0xffffffff,&,rdx,=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:=
│      ╎│   0x000006ee      8b45ec         0x14,rbp,-,[4],rax,=
│      ╎│   0x000006f1      4898           eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}
│      ╎│   0x000006f3      885405f4       dl,0xc,rax,rbp,+,-,=[1]
│      ╎│   0x000006f7      8345ec01       1,0x14,rbp,-,+=[4],31,$o,of,:=,31,$s,sf,:=,$z,zf,:=,31,$c,cf,:=,$p,pf,:=
│      ╎│   ; CODE XREF from main @ 0x6d6
│      ╎└─> 0x000006fb      837dec03       3,0x14,rbp,-,[4],==,$z,zf,:=,32,$b,cf,:=,$p,pf,:=,31,$s,sf,:=,31,$o,of,:=
│      └──< 0x000006ff      7ed7           of,sf,^,zf,|,?{,1752,rip,=,}
│           ;-- rip:
│           0x00000701      488d45f4       0xc,rbp,-,rax,=
│           0x00000705      4889c6         rax,rsi,=
│           0x00000708      488d3da50000.  0xa5,rip,+,rdi,=            ; str.s
│                                                                      ; 0x7b4 ; "%s \n" ; const char *format
│           0x0000070f      b800000000     0,rax,=
│           0x00000714      e867feffff     1408,rip,8,rsp,-=,rsp,=[],rip,= ; sym.imp.printf ; int printf(const char *format)
│           0x00000719      90             ,
│           0x0000071a      488b45f8       0x8,rbp,-,[8],rax,=
│           0x0000071e      644833042528.  0x28,[8],rax,^=,$z,zf,:=,$p,pf,:=,63,$s,sf,:=,0,cf,:=,0,of,:=
│       ┌─< 0x00000727      7405           zf,?{,1838,rip,=,}
│       │   0x00000729      e842feffff     1392,rip,8,rsp,-=,rsp,=[],rip,= ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x727
│       └─> 0x0000072e      c9             rbp,rsp,=,rsp,[8],rbp,=,8,rsp,+=
└           0x0000072f      c3             rsp,[8],rip,=,8,rsp,+=
```
And we can also inspect the memory like when doing debug:
```
[0x000006d8]> pxw @ 0x00177fe8
0x00177fe8  0x64636261 0x31393b39 0x00001960 0x00000000  abcd9;91`.......
0x00177ff8  0x00178000 0x00000000 0x00000000 0x00000000  ................

```

On the next post we'll explore similar topics on a Windows system.