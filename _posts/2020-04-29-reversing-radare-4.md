---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 4 (arrays and strings)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare_4.png
featured_image: assets/images/radare2/radare_4.png
---

Yeahyeah, we are back at it!

Today I'm going to walk you through some very basic data structures such as uni dimensional arrays and char arrays that can be interpreted as strings.

We'll go example by example as I think it is one of the easiest ways to learn and we are going to focus more on understanding the disasm rather than explaining a lot of r2 features.


#### Arrays

Arrays are simple data structures that contain one or more elements of a specific type. Arrays make it easy for us to reference multiple elements with one single tag, instead of having to declare a lot of variables.

Consider the following code:
```
# include <stdio.h>

main(){
 func();
 getchar();     
}

func(){
    int num[5];       
    int sum;            
    num[0] = 200;      
    num[1] = 150;
    num[2] = 100;
    num[3] = -50;
    num[4] = 300;
    sum = num[0] +     num[1] + num[2] + num[3] + num[4];
    printf("SUM IS %d", sum);
}
```
There we declare a numeric array of 5 integers, we can reference those positions by their numeric index, then we can treat each of them as a single variable. So on the practical level there is no much of a difference.

Let's check that out inside r2
```
[0x7f84fc8ab090]> afl
0x562febd98000    5 292  -> 293  sym.imp.__libc_start_main
0x562febd98588    3 23           sym._init
0x562febd985b0    1 6            sym.imp.__stack_chk_fail
0x562febd985c0    1 6            sym.imp.printf
0x562febd985d0    1 6            sym.imp.getchar
0x562febd985e0    1 6            sub.__cxa_finalize_248_5e0
0x562febd985f0    1 43           entry0
0x562febd98620    4 50   -> 40   sym.deregister_tm_clones
0x562febd98660    4 66   -> 57   sym.register_tm_clones
0x562febd986b0    4 49           sym.__do_global_dtors_aux
0x562febd986f0    1 10           entry1.init
0x562febd986fa    1 26           sym.main
0x562febd98714    3 129          sym.funcion
0x562febd987a0    4 101          sym.__libc_csu_init
0x562febd98810    1 2            sym.__libc_csu_fini
0x562febd98814    1 9            sym._fini
0x562febf98fe0    1 1020         reloc.__libc_start_main_224
[0x7f84fc8ab090]> s sym.funcion
[0x562febd98714]> pdf
/ (fcn) sym.funcion 129
|   sym.funcion ();
|           ; var int local_24h @ rbp-0x24
|           ; var int local_20h @ rbp-0x20
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_18h @ rbp-0x18
|           ; var int local_14h @ rbp-0x14
|           ; var int local_10h @ rbp-0x10
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x562febd98703 (sym.main)
|           0x562febd98714      55             push rbp
|           0x562febd98715      4889e5         mov rbp, rsp
|           0x562febd98718      4883ec30       sub rsp, 0x30           ; '0'
|           0x562febd9871c      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x562febd98725      488945f8       mov qword [local_8h], rax
|           0x562febd98729      31c0           xor eax, eax
|           0x562febd9872b      c745e0c80000.  mov dword [local_20h], 0xc8 ; 200
|           0x562febd98732      c745e4960000.  mov dword [local_1ch], 0x96 ; 150
|           0x562febd98739      c745e8640000.  mov dword [local_18h], 0x64 ; 'd' ; 100
|           0x562febd98740      c745ecceffff.  mov dword [local_14h], 0xffffffce ; 4294967246
|           0x562febd98747      c745f02c0100.  mov dword [local_10h], 0x12c ; 300
|           0x562febd9874e      8b55e0         mov edx, dword [local_20h]
|           0x562febd98751      8b45e4         mov eax, dword [local_1ch]
|           0x562febd98754      01c2           add edx, eax
|           0x562febd98756      8b45e8         mov eax, dword [local_18h]
|           0x562febd98759      01c2           add edx, eax
|           0x562febd9875b      8b45ec         mov eax, dword [local_14h]
|           0x562febd9875e      01c2           add edx, eax
|           0x562febd98760      8b45f0         mov eax, dword [local_10h]
|           0x562febd98763      01d0           add eax, edx
|           0x562febd98765      8945dc         mov dword [local_24h], eax
|           0x562febd98768      8b45dc         mov eax, dword [local_24h]
|           0x562febd9876b      89c6           mov esi, eax
|           0x562febd9876d      488d3db00000.  lea rdi, qword str.SUM_IS__d ; 0x562febd98824 ; "SUM IS %d" ; const char * format
|           0x562febd98774      b800000000     mov eax, 0
|           0x562febd98779      e842feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x562febd9877e      90             nop
|           0x562febd9877f      488b4df8       mov rcx, qword [local_8h]
|           0x562febd98783      6448330c2528.  xor rcx, qword fs:[0x28]
|       ,=< 0x562febd9878c      7405           je 0x562febd98793
|       |   0x562febd9878e      e81dfeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x562febd98793      c9             leave
\           0x562febd98794      c3             ret
[0x562febd98714]> 

```
Again, we can break our analysis in diferent parts. If we look close, we can see some "variables" being declared inside the function:

```
           ; var int local_24h @ rbp-0x24
|           ; var int local_20h @ rbp-0x20
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_18h @ rbp-0x18
|           ; var int local_14h @ rbp-0x14
|           ; var int local_10h @ rbp-0x10
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x562febd98703 (sym.main)
|           0x562febd98714      55             push rbp
|           0x562febd98715      4889e5         mov rbp, rsp
|           0x562febd98718      4883ec30       sub rsp, 0x30           ; '0'
|           0x562febd9871c      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x562febd98725      488945f8       mov qword [local_8h], rax
```

As we already saw previously, local_8h is related to the stack guard so no problem there, but we see 6 other variables there, strange right? as we just declared the array and the sum variable.

If we follow the trace of those 6 variables on the code we can see:

```
|           0x562febd9872b      c745e0c80000.  mov dword [local_20h], 0xc8 ; 200
|           0x562febd98732      c745e4960000.  mov dword [local_1ch], 0x96 ; 150
|           0x562febd98739      c745e8640000.  mov dword [local_18h], 0x64 ; 'd' ; 100
|           0x562febd98740      c745ecceffff.  mov dword [local_14h], 0xffffffce ; 4294967246
|           0x562febd98747      c745f02c0100.  mov dword [local_10h], 0x12c ; 300
```
So, those are being initialized to 200, 150, 100, a weird value and 300. Wait what is that weird value? It should be -50 !

mmh.. but if we use rax2

```
red@blue:~/c/chapter4$ rax2 0x0ffffffffffffffce
-50
red@blue:~/c/chapter4$ 

red@blue:~/c/chapter4$ rax2 -50
0xffffffffffffffce
```
Ahh... problem solved. As we see here the compiler interprets the array as a set of variables, allocated one after another in memory. By the way we can easily check that by placing a breakpoint after the initialization is done:

And dump the initial mem address
```
|           0x562febd98747      c745f02c0100.  mov dword [local_10h], 0x12c ; 300
|           ;-- rip:
|           0x562febd9874e b    8b55e0         mov edx, dword [local_20h]

[0x562febd98714]> afvd
var local_8h = 0x7ffcf5d7ad88  0xebc835f94cbbc100   ...L.5..
var local_20h = 0x7ffcf5d7ad70  0x00000096000000c8   ........
var local_1ch = 0x7ffcf5d7ad74  0x0000006400000096   ....d...
var local_18h = 0x7ffcf5d7ad78  0xffffffce00000064   d.......
var local_14h = 0x7ffcf5d7ad7c  0x0000012cffffffce   ....,...
var local_10h = 0x7ffcf5d7ad80  0x0000562f0000012c   ,.../V..
var local_24h = 0x7ffcf5d7ad6c  0x000000c80000562f   /V......


[0x562febd98714]> pxw @ 0x7ffcf5d7ad70
0x7ffcf5d7ad70  0x000000c8 0x00000096 0x00000064 0xffffffce  ........d.......
0x7ffcf5d7ad80  0x0000012c 0x0000562f 0x4cbbc100 0xebc835f9  ,.../V.....L.5..
0x7ffcf5d7ad90  0xf5d7ada0 0x00007ffc 0xebd98708 0x0000562f  ............/V..
```

That's it, all those variables come together in memory one after another, the way we arrays do.

After that, what comes next is not a challenge for us. The edx register is used for storing the sum of all of those numbers, then the variable sum is used for storing the final value and bam! printf.

Let's now check the same exact thing, but using single variables instead:
```
# include <stdio.h>

main(){
 func();
 getchar();     
}

func(){
    int sum;

    int num0 = 200;
    int num1 = 150;
    int num2 = 100;
    int num3 = -50;
    int num4 = 300;
    sum = num0 + num1 + num2 + num3 + num4;
    printf("SUM is %d", sum);

}
```

```
[0x5570354d96a4]> pdf
/ (fcn) sym.func 94
|   sym.func ();
|           ; var int local_18h @ rbp-0x18
|           ; var int local_14h @ rbp-0x14
|           ; var int local_10h @ rbp-0x10
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x5570354d9693 (sym.main)
|           0x5570354d96a4      55             push rbp
|           0x5570354d96a5      4889e5         mov rbp, rsp
|           0x5570354d96a8      4883ec20       sub rsp, 0x20
|           0x5570354d96ac      c745e8c80000.  mov dword [local_18h], 0xc8 ; 200
|           0x5570354d96b3      c745ec960000.  mov dword [local_14h], 0x96 ; 150
|           0x5570354d96ba      c745f0640000.  mov dword [local_10h], 0x64 ; 'd' ; 100
|           0x5570354d96c1      c745f4ceffff.  mov dword [local_ch], 0xffffffce ; 4294967246
|           0x5570354d96c8      c745f82c0100.  mov dword [local_8h], 0x12c ; 300
|           0x5570354d96cf      8b55e8         mov edx, dword [local_18h]
|           0x5570354d96d2      8b45ec         mov eax, dword [local_14h]
|           0x5570354d96d5      01c2           add edx, eax
|           0x5570354d96d7      8b45f0         mov eax, dword [local_10h]
|           0x5570354d96da      01c2           add edx, eax
|           0x5570354d96dc      8b45f4         mov eax, dword [local_ch]
|           0x5570354d96df      01c2           add edx, eax
|           0x5570354d96e1      8b45f8         mov eax, dword [local_8h]
|           0x5570354d96e4      01d0           add eax, edx
|           0x5570354d96e6      8945fc         mov dword [local_4h], eax
|           0x5570354d96e9      8b45fc         mov eax, dword [local_4h]
|           0x5570354d96ec      89c6           mov esi, eax
|           0x5570354d96ee      488d3d9f0000.  lea rdi, qword str.SUM_is__d ; 0x5570354d9794 ; "SUM is %d"
|           0x5570354d96f5      b800000000     mov eax, 0
|           0x5570354d96fa      e851feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x5570354d96ff      90             nop
|           0x5570354d9700      c9             leave
\           0x5570354d9701      c3             ret
[0x5570354d96a4]> 
```

Not much more to explain here... as I said... the same exact thing! So here the compiler has identified that the code does exactly the same and thus decided to treat it the same way...

But you'll be asking yourself ok so that array of 5 positions can be read as 5 independent variables, but what if we have an array of 100 elements? Will it look that weird?

Let's see!

```
# include <stdio.h>

main(){
 func();
 getchar();     
}

func(){

int arr[100];
for (int i=0;i<100;i++){
        arr[i]=i;
}
for (int i=0;i<100;i++){
        printf("val %d",arr[i]);
}
}
```
First, we declare, then we fill it, at the end we print it.

```
:> pdf
/ (fcn) sym.func 160
|   sym.func ();
|           ; var int local_1a8h @ rbp-0x1a8
|           ; var int local_1a4h @ rbp-0x1a4
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x5567f0ed8703 (sym.main)
|           0x5567f0ed8714      55             push rbp
|           0x5567f0ed8715      4889e5         mov rbp, rsp
|           0x5567f0ed8718      4881ecb00100.  sub rsp, 0x1b0
|           0x5567f0ed871f      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x5567f0ed8728      488945f8       mov qword [local_8h], rax
|           0x5567f0ed872c      31c0           xor eax, eax
|           0x5567f0ed872e      c78558feffff.  mov dword [local_1a8h], 0
|       ,=< 0x5567f0ed8738      eb1c           jmp 0x5567f0ed8756
|      .--> 0x5567f0ed873a      8b8558feffff   mov eax, dword [local_1a8h]
|      :|   0x5567f0ed8740      4898           cdqe
|      :|   0x5567f0ed8742      8b9558feffff   mov edx, dword [local_1a8h]
|      :|   0x5567f0ed8748      89948560feff.  mov dword [rbp + rax*4 - 0x1a0], edx
|      :|   0x5567f0ed874f      838558feffff.  add dword [local_1a8h], 1
|      :|      ; JMP XREF from 0x5567f0ed8738 (sym.func)
|      :`-> 0x5567f0ed8756      83bd58feffff.  cmp dword [local_1a8h], 0x63 ; [0x63:4]=-1 ; 'c' ; 99
|      `==< 0x5567f0ed875d      7edb           jle 0x5567f0ed873a
|           0x5567f0ed875f      c7855cfeffff.  mov dword [local_1a4h], 0
|       ,=< 0x5567f0ed8769      eb29           jmp 0x5567f0ed8794
|      .--> 0x5567f0ed876b      8b855cfeffff   mov eax, dword [local_1a4h]
|      :|   0x5567f0ed8771      4898           cdqe
|      :|   0x5567f0ed8773      8b848560feff.  mov eax, dword [rbp + rax*4 - 0x1a0]
|      :|   0x5567f0ed877a      89c6           mov esi, eax
|      :|   0x5567f0ed877c      488d3dc10000.  lea rdi, qword str.val__d ; 0x5567f0ed8844 ; "val %d"
|      :|   0x5567f0ed8783      b800000000     mov eax, 0
|      :|   0x5567f0ed8788      e833feffff     call sym.imp.printf     ; int printf(const char *format)
|      :|   0x5567f0ed878d      83855cfeffff.  add dword [local_1a4h], 1
|      :|      ; JMP XREF from 0x5567f0ed8769 (sym.func)
|      :`-> 0x5567f0ed8794      83bd5cfeffff.  cmp dword [local_1a4h], 0x63 ; [0x63:4]=-1 ; 'c' ; 99
|      `==< 0x5567f0ed879b      7ece           jle 0x5567f0ed876b
|           0x5567f0ed879d      90             nop
|           0x5567f0ed879e      488b4df8       mov rcx, qword [local_8h]
|           0x5567f0ed87a2      6448330c2528.  xor rcx, qword fs:[0x28]
|       ,=< 0x5567f0ed87ab      7405           je 0x5567f0ed87b2
|       |   0x5567f0ed87ad      e8fefdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x5567f0ed87b2      c9             leave
\           0x5567f0ed87b3      c3             ret
:> 
``` 
As expected, we don't see 100 independent variables there, instead we see three of them, the stack guard thing, then a couple more that may correspond to the first and second for indexes.

Instead the program will use registers as indexes, let's inspect that, let's say for the first loop, the one that initializes the array:

```
|           0x5567f0ed872e      c78558feffff.  mov dword [local_1a8h], 0
|       ,=< 0x5567f0ed8738      eb1c           jmp 0x5567f0ed8756
|      .--> 0x5567f0ed873a      8b8558feffff   mov eax, dword [local_1a8h]
|      :|   0x5567f0ed8740      4898           cdqe
```
First of all, it initializes a variable, the "local_1a8h", then it jumps here:
```
|      :`-> 0x5567f0ed8756      83bd58feffff.  cmp dword [local_1a8h], 0x63 ; [0x63:4]=-1 ; 'c' ; 99
|      `==< 0x5567f0ed875d      7edb           jle 0x5567f0ed873a
|           0x5567f0ed875f      c7855cfeffff.  mov dword [local_1a4h], 0
```
After the jump, the program compares the value that has been initialized to 99 (i < 100), then if less than 99 it goes back up to run the code that is inside the loop. If otherwise it is equal or higher, the program will continue.


```
|      .--> 0x5567f0ed873a      8b8558feffff   mov eax, dword [local_1a8h]
|      :|   0x5567f0ed8740      4898           cdqe
|      :|   0x5567f0ed8742      8b9558feffff   mov edx, dword [local_1a8h]
|      :|   0x5567f0ed8748      89948560feff.  mov dword [rbp + rax*4 - 0x1a0], edx
|      :|   0x5567f0ed874f      838558feffff.  add dword [local_1a8h], 1

```
First, the program moves the content of the value (i) to eax, then as in this case eax is just the 32 bit part of RAX, it uses cdqe to the value to work well in this 64 bit mode. 

*the more you know: In 64-bit mode, the default operation size is the size of the destination register. Use of the REX.W prefix promotes this instruction (CDQE when promoted) to operate on 64-bit operands. In which case, CDQE copies the sign (bit 31) of the doubleword in the EAX register into the high 32 bits of RAX.

After that, it moves the result to edx (edx is used as a temp register here) and it finally stores it in its position inside the array.

But how is that position on the array calculated? We have this: [rbp + rax*4 - 0x1a0], the same can be represented as: [(rbp - 0x1a0)   + rax*4] And as we can easily see: (rbp - 0x1a0) is just a place inside of memory, a space that has been reserved in memory for the array,

After that we have rax*4 being added on every iteration, as as we know, at that point rax will host the value of our variable (i)  as an int has a size of 4 the value of rax will be multiplied by 4 to correctly allocate the int on its position inside the array.

So brief, (rbp - 0x1a0) is the base addr of the array and rax*4 is the index

The rest of the code, same thing partner


#### Initializing arrays

Arrays can be pre-initialized, but on this case it will be the same:
```
# include <stdio.h>

main(){
 func();
 getchar();     
}

func(){
    int sum=0;
    int i;

    int num[5] ={200, 150, 100, -50, 300};
        for(i=0;i<=4;i++) sum += num[i]; 
                printf("SUM is %d", sum);
        }
```

```
[0x00000714]> pdf
/ (fcn) sym.func 141
|   sym.func ();
|           ; var int local_28h @ rbp-0x28
|           ; var int local_24h @ rbp-0x24
|           ; var int local_20h @ rbp-0x20
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_18h @ rbp-0x18
|           ; var int local_14h @ rbp-0x14
|           ; var int local_10h @ rbp-0x10
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x00000703 (sym.main)
|           0x00000714      55             push rbp
|           0x00000715      4889e5         mov rbp, rsp
|           0x00000718      4883ec30       sub rsp, 0x30               ; '0'
|           0x0000071c      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x19b8 ; '('
|           0x00000725      488945f8       mov qword [local_8h], rax
|           0x00000729      31c0           xor eax, eax
|           0x0000072b      c745d8000000.  mov dword [local_28h], 0
|           0x00000732      c745e0c80000.  mov dword [local_20h], 0xc8
|           0x00000739      c745e4960000.  mov dword [local_1ch], 0x96
|           0x00000740      c745e8640000.  mov dword [local_18h], 0x64 ; 'd'
|           0x00000747      c745ecceffff.  mov dword [local_14h], 0xffffffce ; 4294967246
|           0x0000074e      c745f02c0100.  mov dword [local_10h], 0x12c
|           0x00000755      c745dc000000.  mov dword [local_24h], 0
[...]
```
Saaame thing :)



#### Char arrays / strings

Things start to get a bit more interesting here, this time we will declare a char array that can be interpreted as a string, we'll use scanf to read fromuser input:
```
# include <stdio.h>

main(){
 func();
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
On this case, we have just one variable the local_30h. 
```
[0x55d494124789]> pdf
/ (fcn) sym.func 111
|   sym.func ();
|           ; var int local_30h @ rbp-0x30
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x55d494124773 (sym.main)
|           0x55d494124789      55             push rbp
|           0x55d49412478a      4889e5         mov rbp, rsp
|           0x55d49412478d      4883ec30       sub rsp, 0x30           ; '0'
|           0x55d494124791      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x55d49412479a      488945f8       mov qword [local_8h], rax
|           0x55d49412479e      31c0           xor eax, eax
|           0x55d4941247a0      488d3ddd0000.  lea rdi, qword str.Name_: ; 0x55d494124884 ; "Name?: "
|           0x55d4941247a7      b800000000     mov eax, 0
|           0x55d4941247ac      e86ffeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55d4941247b1      488d45d0       lea rax, qword [local_30h]
|           0x55d4941247b5      4889c6         mov rsi, rax
|           0x55d4941247b8      488d3dcd0000.  lea rdi, qword [0x55d49412488c] ; "%s"
|           0x55d4941247bf      b800000000     mov eax, 0
|           0x55d4941247c4      e877feffff     call sym.imp.__isoc99_scanf
|           0x55d4941247c9      488d45d0       lea rax, qword [local_30h]
|           0x55d4941247cd      4889c6         mov rsi, rax
|           0x55d4941247d0      488d3db80000.  lea rdi, qword str.Hi___s ; 0x55d49412488f ; "Hi, %s\n"
|           0x55d4941247d7      b800000000     mov eax, 0
|           0x55d4941247dc      e83ffeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55d4941247e1      90             nop
|           0x55d4941247e2      488b55f8       mov rdx, qword [local_8h]
|           0x55d4941247e6      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x55d4941247ef      7405           je 0x55d4941247f6
|       |   0x55d4941247f1      e81afeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x55d4941247f6      c9             leave
\           0x55d4941247f7      c3             ret
[0x55d494124789]> 
```
local_30h is 0x30 (48 dec) bytes away from the rbp, so it makes a lot of sense that this var is the text char array that will allocate our string.

We can place a breakpoint at the point where it is referenced for the first time, right before jumping inside the scanf.
```
[0x55d494124789]> db 0x55d4941247b5
[0x55d494124789]> dc
hit breakpoint at: 55d4941247b5
[0x55d494124789]> 

[0x55d494124789]> dr
rax = 0x7ffdfa5e7920

[0x55d494124789]> pxw @ 0x7ffdfa5e7920
0x7ffdfa5e7920  0x00000001 0x00000000 0x9412484d 0x000055d4  ........MH...U..
0x7ffdfa5e7930  0x032ee9a0 0x00007ff9 0x00000000 0x00000000  ................
``` 
So let's note this address: 0x7ffdfa5e7920 as our string will be stored there.
```
[0x55d494124789]> db 0x55d4941247cd
[0x55d494124789]> dc
Name?: ARTIK
hit breakpoint at: 55d4941247cd
[0x55d4941247cd]> pxw @ 0x7ffdfa5e7920
0x7ffdfa5e7920  0x49545241 0x0000004b 0x9412484d 0x000055d4  ARTIK...MH...U..
``` 
There it is! The rest of the code is quite simple, local_30h will be passed again to printf and the output will be printed out.

As usual, we can access char array elements individually by using an index, let's consider this one:
```
# include <stdio.h>

main(){
 func();
 getchar();
  getchar();     
}

func(){

    char text[40];        

    printf("Name?: ");
    scanf("%s", text);
    printf("Hey, %s. First letter: %c\n", text, text[0]);
    printf("Ho, %s. Second letter: %c\n", text, text[1]);
}
```
That program basically declares a char array, reads from the user input to store the text right there, and then accesses the array both "globally" and also by index.

Inside radare2 that looks like this one.
```
[0x55d2fe6d3789]> pdf
/ (fcn) sym.func 149
|   sym.func ();
|           ; var int local_30h @ rbp-0x30
|           ; var int local_2fh @ rbp-0x2f
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x55d2fe6d3773 (sym.main)
|           0x55d2fe6d3789      55             push rbp
|           0x55d2fe6d378a      4889e5         mov rbp, rsp
|           0x55d2fe6d378d      4883ec30       sub rsp, 0x30           ; '0'
|           0x55d2fe6d3791      64488b042528.  mov rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x55d2fe6d379a      488945f8       mov qword [local_8h], rax
|           0x55d2fe6d379e      31c0           xor eax, eax
|           0x55d2fe6d37a0      488d3dfd0000.  lea rdi, qword str.Name_: ; 0x55d2fe6d38a4 ; "Name?: "
|           0x55d2fe6d37a7      b800000000     mov eax, 0
|           0x55d2fe6d37ac      e86ffeffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55d2fe6d37b1      488d45d0       lea rax, qword [local_30h]
|           0x55d2fe6d37b5      4889c6         mov rsi, rax
|           0x55d2fe6d37b8      488d3ded0000.  lea rdi, qword [0x55d2fe6d38ac] ; "%s"
|           0x55d2fe6d37bf      b800000000     mov eax, 0
|           0x55d2fe6d37c4      e877feffff     call sym.imp.__isoc99_scanf
|           0x55d2fe6d37c9      0fb645d0       movzx eax, byte [local_30h]
|           0x55d2fe6d37cd      0fbed0         movsx edx, al
|           0x55d2fe6d37d0      488d45d0       lea rax, qword [local_30h]
|           0x55d2fe6d37d4      4889c6         mov rsi, rax
|           0x55d2fe6d37d7      488d3dd10000.  lea rdi, qword str.Hey___s._First_letter:__c ; 0x55d2fe6d38af ; "Hey, %s. First letter: %c\n"
|           0x55d2fe6d37de      b800000000     mov eax, 0
|           0x55d2fe6d37e3      e838feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55d2fe6d37e8      0fb645d1       movzx eax, byte [local_2fh]
|           0x55d2fe6d37ec      0fbed0         movsx edx, al
|           0x55d2fe6d37ef      488d45d0       lea rax, qword [local_30h]
|           0x55d2fe6d37f3      4889c6         mov rsi, rax
|           0x55d2fe6d37f6      488d3dcd0000.  lea rdi, qword str.Ho___s._Second_letter:__c ; 0x55d2fe6d38ca ; "Ho, %s. Second letter: %c\n"
|           0x55d2fe6d37fd      b800000000     mov eax, 0
|           0x55d2fe6d3802      e819feffff     call sym.imp.printf     ; int printf(const char *format)
|           0x55d2fe6d3807      90             nop
|           0x55d2fe6d3808      488b4df8       mov rcx, qword [local_8h]
|           0x55d2fe6d380c      6448330c2528.  xor rcx, qword fs:[0x28]
|       ,=< 0x55d2fe6d3815      7405           je 0x55d2fe6d381c
|       |   0x55d2fe6d3817      e8f4fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x55d2fe6d381c      c9             leave
\           0x55d2fe6d381d      c3             ret
[0x55d2fe6d3789]> 
```
First of all, we detect two variables: 
```
/ (fcn) sym.func 149
|   sym.func ();
|           ; var int local_30h @ rbp-0x30
|           ; var int local_2fh @ rbp-0x2f
|           ; var int local_8h @ rbp-0x8
```
The first one, we already know it, this may be the base addr of the char-array, but then the other one... it is located just one byte away from the base addr... let's take that into account. We cen even rename those to make it clearer.

We are already familiar with how the "string" is read by scanf:
```
|           0x55d2fe6d37b1      488d45d0       lea rax, qword [text_array]
|           0x55d2fe6d37b5      4889c6         mov rsi, rax
|           0x55d2fe6d37b8      488d3ded0000.  lea rdi, qword [0x55d2fe6d38ac] ; "%s"
|           0x55d2fe6d37bf      b800000000     mov eax, 0
|           0x55d2fe6d37c4      e877feffff     call sym.imp.__isoc99_scanf
```
But then we get this:
```
|           0x55d2fe6d37c9      0fb645d0       movzx eax, byte [text_array]
|           0x55d2fe6d37cd      0fbed0         movsx edx, al
|           0x55d2fe6d37d0      488d45d0       lea rax, qword [text_array]
|           0x55d2fe6d37d4      4889c6         mov rsi, rax
|           0x55d2fe6d37d7      488d3dd10000.  lea rdi, qword str.Hey___s._First_letter:__c ; 0x55d2fe6d38af ; "Hey, %s. First letter: %c\n"
|           0x55d2fe6d37de      b800000000     mov eax, 0
|           0x55d2fe6d37e3      e838feffff     call sym.imp.printf     ; int printf(const char *format)
```
On the first instruction we see movzx extracting the first byte from text_array (Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.)

Then that byte (al) is moved to edx with movsx (Copies the contents of the source operand (register or memory location) to the destination operand (register) and sign extends the value to 16 or 32 bits)

We can easily deduce that this basically extracts the first character of the array, then the pointer to that array gets moved to rsi through rax and we call printf.

That next block of code does the same thing, using that "pos1" variable we detected instead, as ?index?. Let's see, this time we can debug it for an easier visualization.


```
|           0x55d2fe6d37e8      0fb645d1       movzx eax, byte [pos1]
|           0x55d2fe6d37ec      0fbed0         movsx edx, al
|           ;-- rip:
|           0x55d2fe6d37ef b    488d45d0       lea rax, qword [text_array]
|           0x55d2fe6d37f3      4889c6         mov rsi, rax
|           0x55d2fe6d37f6      488d3dcd0000.  lea rdi, qword str.Ho___s._Second_letter:__c ; 0x55d2fe6d38ca ; "Ho, %s. Second letter: %c\n"
|           0x55d2fe6d37fd      b800000000     mov eax, 0
```
After placing a breakpoint right before the movsx, if we inspect the register we'll see that
```
[0x55d2fe6d37d0]> dr
rax = 0x00000052
rbx = 0x00000000
rcx = 0x00000000
rdx = 0x00000052
```
Exactly, rdx (and al) = 52 = ascii code for R being ARTIK the input.

Mystery solved :)
