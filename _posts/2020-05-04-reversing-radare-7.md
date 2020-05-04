---
layout: post
title:  "Reverse engineering 32 and 64 bits binaries with Radare2 - 7 (struct arrays, r2pm and patching)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_8.png
featured_image: assets/images/radare2/radare2_8.png
---
So today we are going to work with a more complete example related to structs, the goal is to correctly understand how the program works interally and explore a couple of r2 feats more.
```
#include <stdio.h>

const int MAX = 20;
"td struct stud { char fletter; int age; float mark;};"
struct stud
	{
		char fletter;
		int age;
		float mark;
	};

main(){
	func1();
	getchar();
}


void showstudents(struct stud students[], int n){

	printf("Showing students: \n");

	for(int i = 0; i < n; i++){
		printf("Student num %d: ", i);
		printf("First letter = %c ", students[i].fletter);
		printf("Age = %d ", students[i].age);
		printf("Mark = %f \n", students[i].mark);
	}


}


int addstudents(struct stud students[], int i){
	printf("Round: %d \n", i);

	if(i > MAX){
		printf("Students list is FULL\n");
		return -1;
	}
	else{
		printf("First letter?\n");
		scanf(" %c",&students[i].fletter);

		printf("Age?\n");
		scanf(" %i",&students[i].age);

		printf("Mark?\n");
		scanf(" %f",&students[i].mark);

		

		return i+1;
	}

}

func1(){

	struct stud students[MAX];

	int i = 0;
	char q =' ';

	while(q != 'q' && i!=-1){
		printf("Action? (q=Quit, a=Add, s=ShowAll)\n");

		scanf(" %c", &q);
		if(q == 'a'){
			i = addstudents(students,i);

			
			
		}
        
		
	}
}
```

Lets check what functions do we have here:
```
[0x000009c0]> afl
0x000006a0    1 42           entry0
0x000006d0    4 50   -> 40   sym.deregister_tm_clones
0x00000710    4 66   -> 57   sym.register_tm_clones
0x00000760    5 58   -> 51   sym.__do_global_dtors_aux
0x000007a0    1 10           entry.init0
0x00000b90    1 2            sym.__libc_csu_fini
0x000009c0    8 352          sym.func1
0x00000b94    1 9            sym._fini
0x000007c4    4 240          sym.showstudents
0x00000b20    4 101          sym.__libc_csu_init
0x000008b4    4 268          sym.addstudents
0x000007aa    1 26           main
0x00000670    1 6            sym.imp.getchar
0x00000618    3 23           sym._init
0x00000640    1 6            sym.imp.puts
0x00000650    1 6            sym.imp.__stack_chk_fail
0x00000660    1 6            sym.imp.printf
0x00000000    5 97   -> 123  loc.imp._ITM_deregisterTMCloneTable
0x00000680    1 6            sym.imp.__isoc99_scanf
```
Good, so the most relevant functions we can see are showstudents, addstudents and func1, the rest relate to the stdio lib and the program entry point. As we already know, the program kind of "begins" at sym.func1, so let's see:

```
[0x000006a0]> s sym.func1
[0x000009c0]> pdf
            ; CALL XREF from main @ 0x7b3
┌ 352: sym.func1 ();
│           ; var int64_t var_2dh @ rbp-0x2d
│           ; var uint32_t var_2ch @ rbp-0x2c
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t canary @ rbp-0x18
│           ; var int64_t var_10h @ rbp-0x10
│           0x000009c0      55             push rbp
│           0x000009c1      4889e5         mov rbp, rsp
│           0x000009c4      4154           push r12
│           0x000009c6      53             push rbx
│           0x000009c7      4883ec20       sub rsp, 0x20
│           0x000009cb      64488b3c2528.  mov rdi, qword fs:[0x28]
│           0x000009d4      48897de8       mov qword [canary], rdi
│           0x000009d8      31ff           xor edi, edi
│           0x000009da      4889e6         mov rsi, rsp
│           0x000009dd      4989f4         mov r12, rsi
│           0x000009e0      be14000000     mov esi, 0x14
│           0x000009e5      4863f6         movsxd rsi, esi
│           0x000009e8      4883ee01       sub rsi, 1
│           0x000009ec      488975d8       mov qword [var_28h], rsi
│           0x000009f0      be14000000     mov esi, 0x14
│           0x000009f5      4863f6         movsxd rsi, esi
│           0x000009f8      4889f0         mov rax, rsi
│           0x000009fb      ba00000000     mov edx, 0
│           0x00000a00      486bfa60       imul rdi, rdx, 0x60
│           0x00000a04      486bf000       imul rsi, rax, 0
│           0x00000a08      4801fe         add rsi, rdi
│           0x00000a0b      bf60000000     mov edi, 0x60               ; '`'
│           0x00000a10      48f7e7         mul rdi
│           0x00000a13      4801d6         add rsi, rdx
│           0x00000a16      4889f2         mov rdx, rsi
│           0x00000a19      b814000000     mov eax, 0x14
│           0x00000a1e      4863d0         movsxd rdx, eax
│           0x00000a21      4889d0         mov rax, rdx
│           0x00000a24      4801c0         add rax, rax
│           0x00000a27      4801d0         add rax, rdx
│           0x00000a2a      48c1e002       shl rax, 2
│           0x00000a2e      b814000000     mov eax, 0x14
│           0x00000a33      4898           cdqe
│           0x00000a35      4889c1         mov rcx, rax
│           0x00000a38      bb00000000     mov ebx, 0
│           0x00000a3d      486bd360       imul rdx, rbx, 0x60
│           0x00000a41      486bc100       imul rax, rcx, 0
│           0x00000a45      488d3402       lea rsi, [rdx + rax]
│           0x00000a49      b860000000     mov eax, 0x60               ; '`'
│           0x00000a4e      48f7e1         mul rcx
│           0x00000a51      488d0c16       lea rcx, [rsi + rdx]
│           0x00000a55      4889ca         mov rdx, rcx
│           0x00000a58      b814000000     mov eax, 0x14
│           0x00000a5d      4863d0         movsxd rdx, eax
│           0x00000a60      4889d0         mov rax, rdx
│           0x00000a63      4801c0         add rax, rax
│           0x00000a66      4801d0         add rax, rdx
│           0x00000a69      48c1e002       shl rax, 2
│           0x00000a6d      488d5003       lea rdx, [rax + 3]
│           0x00000a71      b810000000     mov eax, 0x10
│           0x00000a76      4883e801       sub rax, 1
│           0x00000a7a      4801d0         add rax, rdx
│           0x00000a7d      bb10000000     mov ebx, 0x10
│           0x00000a82      ba00000000     mov edx, 0
│           0x00000a87      48f7f3         div rbx
│           0x00000a8a      486bc010       imul rax, rax, 0x10
│           0x00000a8e      4829c4         sub rsp, rax
│           0x00000a91      4889e0         mov rax, rsp
│           0x00000a94      4883c003       add rax, 3
│           0x00000a98      48c1e802       shr rax, 2
│           0x00000a9c      48c1e002       shl rax, 2
│           0x00000aa0      488945e0       mov qword [var_20h], rax
│           0x00000aa4      c745d4000000.  mov dword [var_2ch], 0
│           0x00000aab      c645d320       mov byte [var_2dh], 0x20    ; "@"
│       ┌─< 0x00000aaf      eb40           jmp 0xaf1
│       │   ; CODE XREF from sym.func1 @ 0xafd
│      ┌──> 0x00000ab1      488d3d880100.  lea rdi, str.Action___q_Quit__a_Add__s_ShowAll ; 0xc40 ; "Action? (q=Quit, a=Add, s=ShowAll)" ; const char *s
│      ╎│   0x00000ab8      e883fbffff     call sym.imp.puts           ; int puts(const char *s)
│      ╎│   0x00000abd      488d45d3       lea rax, [var_2dh]
│      ╎│   0x00000ac1      4889c6         mov rsi, rax
│      ╎│   0x00000ac4      488d3d5e0100.  lea rdi, [0x00000c29]       ; " %c" ; const char *format
│      ╎│   0x00000acb      b800000000     mov eax, 0
│      ╎│   0x00000ad0      e8abfbffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      ╎│   0x00000ad5      0fb645d3       movzx eax, byte [var_2dh]
│      ╎│   0x00000ad9      3c61           cmp al, 0x61
│     ┌───< 0x00000adb      7514           jne 0xaf1
│     │╎│   0x00000add      488b45e0       mov rax, qword [var_20h]
│     │╎│   0x00000ae1      8b55d4         mov edx, dword [var_2ch]
│     │╎│   0x00000ae4      89d6           mov esi, edx                ; signed int64_t arg2
│     │╎│   0x00000ae6      4889c7         mov rdi, rax                ; int64_t arg1
│     │╎│   0x00000ae9      e8c6fdffff     call sym.addstudents
│     │╎│   0x00000aee      8945d4         mov dword [var_2ch], eax
│     │╎│   ; CODE XREFS from sym.func1 @ 0xaaf, 0xadb
│     └─└─> 0x00000af1      0fb645d3       movzx eax, byte [var_2dh]
│      ╎    0x00000af5      3c71           cmp al, 0x71
│      ╎┌─< 0x00000af7      7406           je 0xaff
│      ╎│   0x00000af9      837dd4ff       cmp dword [var_2ch], 0xffffffff
│      └──< 0x00000afd      75b2           jne 0xab1
│       │   ; CODE XREF from sym.func1 @ 0xaf7
│       └─> 0x00000aff      4c89e4         mov rsp, r12
│           0x00000b02      90             nop
│           0x00000b03      488b5de8       mov rbx, qword [canary]
│           0x00000b07      6448331c2528.  xor rbx, qword fs:[0x28]
│       ┌─< 0x00000b10      7405           je 0xb17
│       │   0x00000b12      e839fbffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from sym.func1 @ 0xb10
│       └─> 0x00000b17      488d65f0       lea rsp, [var_10h]
│           0x00000b1b      5b             pop rbx
│           0x00000b1c      415c           pop r12
│           0x00000b1e      5d             pop rbp
└           0x00000b1f      c3             ret
```
Now that starts to look complex, this block is big. On situations like this one you may be interested in examining the program in a more C-like style and try to get the big picture, decompilers can help with that. Radare2 has a nice decompiler called r2dec, that can be installed by using the radare2 package manager, r2pm.

We can install a package, radec in this case with this:
```
r2pm init
r2pm install r2dec
``` 
And then with pdd we can run the decompiler
```
0x000009c0]> pdd
/* r2dec pseudo code output */
/* struct1 @ 0x9c0 */
#include <stdint.h>
 
int64_t func1 (void) {
    int64_t var_2dh;
    uint32_t var_2ch;
    int64_t var_28h;
    int64_t var_20h;
    int64_t canary;
    int64_t var_10h;
    rdi = *(fs:0x28);
    canary = *(fs:0x28);
    edi = 0;
    rsi = rsp;
    r12 = rsp;
    esi = 0x14;
    rsi = (int64_t) esi;
    rsi--;
    var_28h = rsi;
    esi = 0x14;
    rsi = (int64_t) esi;
    rax = rsi;
    edx = 0;
    rdi = rdx * 0x60;
    rsi = rax * 0;
    rsi += rdi;
    edi = 0x60;
    rdx:rax = rax * rdi;
    rsi += rdx;
    rdx = rsi;
    eax = 0x14;
    rdx = (int64_t) eax;
    rax = rdx;
    rax += rax;
    rax += rdx;
    rax <<= 2;
    eax = 0x14;
    rax = (int64_t) eax;
    rcx = rax;
    ebx = 0;
    rdx = rbx * 0x60;
    rax = rcx * 0;
    rsi = rdx + rax;
    eax = 0x60;
    rdx:rax = rax * rcx;
    rcx = rsi + rdx;
    rdx = rcx;
    eax = 0x14;
    rdx = (int64_t) eax;
    rax = rdx;
    rax += rax;
    rax += rdx;
    rax <<= 2;
    rdx = rax + 3;
    eax = 0x10;
    rax--;
    rax += rdx;
    ebx = 0x10;
    edx = 0;
    rax = rdx:rax / rbx;
    rdx = rdx:rax % rbx;
    rax *= 0x10;
    rax = rsp;
    rax += 3;
    rax >>= 2;
    rax <<= 2;
    var_20h = rax;
    var_2ch = 0;
    var_2dh = 0x20;
    while (var_2ch != 0xffffffff) {
        puts ("Action? (q=Quit, a=Add, s=ShowAll)");
        rax = &var_2dh;
        rsi = rax;
        rdi = 0x00000c29;
        eax = 0;
        isoc99_scanf ();
        eax = (int32_t) var_2dh;
        if (al == 0x61) {
            rax = var_20h;
            edx = var_2ch;
            esi = var_2ch;
            rdi = rax;
            showstudents ();
            var_2ch++;
        }
        eax = (int32_t) var_2dh;
        if (al == 0x71) {
            goto label_0;
        }
    }
label_0:
    rbx = canary;
    rbx ^= *(fs:0x28);
    if (var_2ch != 0xffffffff) {
        stack_chk_fail ();
    }
    rsp = &var_10h;
    return rax;
}
```
In this example, we encounter the first project where we will skip some parts or better said, we will get the generla pic and then only focus on stratic areas/aspects of the program. Based on what we saw when running the decompiler we can see that, the function sets the stack canary them runs a big chunk of calculations then sets the result in var_20h and initializes a couple of variables var_2ch at zero and var_2dh with 0x20 (ASCII space ' ') so as we already have the original source, we can rapidly deduce that those correspond to the initialization of the variables of the function. And what's stored at var_20h should be the base addr of the array of structs, knowing that this is the base addr of the array of structs we can better understand the whole chunk of operations that come right before. If we pay more atention into them we can easily detect that:
```
│           0x000009e0      be14000000     mov esi, 0x14
│           0x000009e5      4863f6         movsxd rsi, esi
│           0x000009e8      4883ee01       sub rsi, 1
│           0x000009ec      488975d8       mov qword [var_28h], rsi
│           0x000009f0      be14000000     mov esi, 0x14
│           0x000009f5      4863f6         movsxd rsi, esi
│           0x000009f8      4889f0         mov rax, rsi
│           0x000009fb      ba00000000     mov edx, 0
│           0x00000a00      486bfa60       imul rdi, rdx, 0x60
│           0x00000a04      486bf000       imul rsi, rax, 0
│           0x00000a08      4801fe         add rsi, rdi
│           0x00000a0b      bf60000000     mov edi, 0x60               ; '`'
│           0x00000a10      48f7e7         mul rdi
│           0x00000a13      4801d6         add rsi, rdx
│           0x00000a16      4889f2         mov rdx, rsi
│           0x00000a19      b814000000     mov eax, 0x14
│           0x00000a1e      4863d0         movsxd rdx, eax
│           0x00000a21      4889d0         mov rax, rdx
│           0x00000a24      4801c0         add rax, rax
│           0x00000a27      4801d0         add rax, rdx
│           0x00000a2a      48c1e002       shl rax, 2
│           0x00000a2e      b814000000     mov eax, 0x14
```
0x14 (dec 20) is repeated several times, so what the program is doing is basically "allocating" enough space for the whole array to be stored in memory or better said it calculates a start address for the structure, it can't just reference a variable with ebp-20 or something cause our structure has many values within each one of different size. Another thing to note here is that, as you see no function is called on that code chunk, so it looks like nothing that relevant the algorithm logic is happening I don't know, maybe yes, but some times when you see chunks like that one it generally means stuff related to mem addr calculation or math operations related to variables (use your common sense bro. Also, always pay attention to static values like those 0x14 (or the ascii space, etc) that you see there, they might indicate the size of data structures, indexes, variable initializations, values to be compared (limits) etc etc. Again, most of the time you don't need to understand the 100% of the code instruction by instruction, if you have experience and you get the big picture, you can quickly focus on the strategic parts.

Ok let's go so now we know that the function starts with some mem addr calculation and it also initializes some variables, then it looks like it jumps into a while loop:

```
│           0x00000aab      c645d320       mov byte [var_2dh], 0x20    ; "@"
│       ┌─< 0x00000aaf      eb40           jmp 0xaf1
│       │   ; CODE XREF from sym.func1 @ 0xafd
│      ┌──> 0x00000ab1      488d3d880100.  lea rdi, str.Action___q_Quit__a_Add__s_ShowAll ; 0xc40 ; "Action? (q=Quit, a=Add, s=ShowAll)" ; const char *s
│      ╎│   0x00000ab8      e883fbffff     call sym.imp.puts           ; int puts(const char *s)
│      ╎│   0x00000abd      488d45d3       lea rax, [var_2dh]
│      ╎│   0x00000ac1      4889c6         mov rsi, rax
│      ╎│   0x00000ac4      488d3d5e0100.  lea rdi, [0x00000c29]       ; " %c" ; const char *format
│      ╎│   0x00000acb      b800000000     mov eax, 0
│      ╎│   0x00000ad0      e8abfbffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      ╎│   0x00000ad5      0fb645d3       movzx eax, byte [var_2dh]
│      ╎│   0x00000ad9      3c61           cmp al, 0x61
│     ┌───< 0x00000adb      7514           jne 0xaf1
│     │╎│   0x00000add      488b45e0       mov rax, qword [var_20h]
│     │╎│   0x00000ae1      8b55d4         mov edx, dword [var_2ch]
│     │╎│   0x00000ae4      89d6           mov esi, edx                ; signed int64_t arg2
│     │╎│   0x00000ae6      4889c7         mov rdi, rax                ; int64_t arg1
│     │╎│   0x00000ae9      e8c6fdffff     call sym.addstudents
│     │╎│   0x00000aee      8945d4         mov dword [var_2ch], eax
│     │╎│   ; CODE XREFS from sym.func1 @ 0xaaf, 0xadb
│     └─└─> 0x00000af1      0fb645d3       movzx eax, byte [var_2dh]
│      ╎    0x00000af5      3c71           cmp al, 0x71
│      ╎┌─< 0x00000af7      7406           je 0xaff
│      ╎│   0x00000af9      837dd4ff       cmp dword [var_2ch], 0xffffffff
│      └──< 0x00000afd      75b2           jne 0xab1
│       │   ; CODE XREF from sym.func1 @ 0xaf7
│       └─> 0x00000aff      4c89e4         mov rsp, r12
```
Then, again, we already know how the following works (or we should)
```
│      ┌──> 0x00000ab1      488d3d880100.  lea rdi, str.Action___q_Quit__a_Add__s_ShowAll ; 0xc40 ; "Action? (q=Quit, a=Add, s=ShowAll)" ; const char *s
│      ╎│   0x00000ab8      e883fbffff     call sym.imp.puts           ; int puts(const char *s)
│      ╎│   0x00000abd      488d45d3       lea rax, [var_2dh]
│      ╎│   0x00000ac1      4889c6         mov rsi, rax
│      ╎│   0x00000ac4      488d3d5e0100.  lea rdi, [0x00000c29]       ; " %c" ; const char *format
│      ╎│   0x00000acb      b800000000     mov eax, 0
│      ╎│   0x00000ad0      e8abfbffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      ╎│   0x00000ad5      0fb645d3       movzx eax, byte [var_2dh]
│      ╎│   0x00000ad9      3c61           cmp al, 0x61
│     ┌───< 0x00000adb      7514           jne 0xaf1
│     │╎│   0x00000add      488b45e0       mov rax, qword [var_20h]
```
By the way the string that gets printed already tells us what's going on on that block of code. It reads the user input (option) (quit, add, show) and as it compares the input with 0x61 (ascii a) it sure checks the input and will perform an action according to that input.

So let's see what happens when user inputs 'a' (add)
```
│     │╎│   0x00000add      488b45e0       mov rax, qword [var_20h]
│     │╎│   0x00000ae1      8b55d4         mov edx, dword [var_2ch]
│     │╎│   0x00000ae4      89d6           mov esi, edx                ; signed int64_t arg2
│     │╎│   0x00000ae6      4889c7         mov rdi, rax                ; int64_t arg1
│     │╎│   0x00000ae9      e8c6fdffff     call sym.addstudents
│     │╎│   0x00000aee      8945d4         mov dword [var_2ch], eax

```
The contents of var_20h and var_2ch get passed as parameters. As we already know var_20h represents (or that is what we think) the pointer to the struct array, then var_2ch as we saw is initialized to zero... and it gets updated with the value of eax so we can assume that it is the counter, it is passed to the addstudents function to indicate the current position we are working on.

Then, after that, nothing much more, the loop goes on again, the program does a couple of cmps

```
│      ╎    0x00000af5      3c71           cmp al, 0x71
│      ╎┌─< 0x00000af7      7406           je 0xaff
│      ╎│   0x00000af9      837dd4ff       cmp dword [var_2ch], 0xffffffff
│      └──< 0x00000afd      75b2           jne 0xab1
```
That represent the q != 'q' && i!=-1 condition, as it is a && the condition will be false if q=='q' and it won't need to check for i!=-1 that is why we have those two cmp chained that way.

So said that, we can no jump into the addstudents function to better inspect how it works.

```
[0x000008b4]> pdf
            ; CALL XREF from sym.func1 @ 0xae9
┌ 268: sym.addstudents (int64_t arg1, signed int64_t arg2);
│           ; var signed int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int64_t arg1 @ rdi
│           ; arg signed int64_t arg2 @ rsi
│           0x000008b4      55             push rbp
│           0x000008b5      4889e5         mov rbp, rsp
│           0x000008b8      4883ec10       sub rsp, 0x10
│           0x000008bc      48897df8       mov qword [var_8h], rdi     ; arg1
│           0x000008c0      8975f4         mov dword [var_ch], esi     ; arg2
│           0x000008c3      8b45f4         mov eax, dword [var_ch]
│           0x000008c6      89c6           mov esi, eax
│           0x000008c8      488d3d2a0300.  lea rdi, str.Round:__d      ; 0xbf9 ; "Round: %d \n" ; const char *format
│           0x000008cf      b800000000     mov eax, 0
│           0x000008d4      e887fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x000008d9      b814000000     mov eax, 0x14
│           0x000008de      3945f4         cmp dword [var_ch], eax
│       ┌─< 0x000008e1      7e16           jle 0x8f9
│       │   0x000008e3      488d3d1b0300.  lea rdi, str.Students_list_is_FULL ; 0xc05 ; "Students list is FULL" ; const char *s
│       │   0x000008ea      e851fdffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x000008ef      b8ffffffff     mov eax, 0xffffffff         ; -1
│      ┌──< 0x000008f4      e9c5000000     jmp 0x9be
│      ││   ; CODE XREF from sym.addstudents @ 0x8e1
│      │└─> 0x000008f9      488d3d1b0300.  lea rdi, str.First_letter   ; 0xc1b ; "First letter?" ; const char *s
│      │    0x00000900      e83bfdffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x00000905      8b45f4         mov eax, dword [var_ch]
│      │    0x00000908      4863d0         movsxd rdx, eax
│      │    0x0000090b      4889d0         mov rax, rdx
│      │    0x0000090e      4801c0         add rax, rax
│      │    0x00000911      4801d0         add rax, rdx
│      │    0x00000914      48c1e002       shl rax, 2
│      │    0x00000918      4889c2         mov rdx, rax
│      │    0x0000091b      488b45f8       mov rax, qword [var_8h]
│      │    0x0000091f      4801d0         add rax, rdx
│      │    0x00000922      4889c6         mov rsi, rax
│      │    0x00000925      488d3dfd0200.  lea rdi, [0x00000c29]       ; " %c" ; const char *format
│      │    0x0000092c      b800000000     mov eax, 0
│      │    0x00000931      e84afdffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      │    0x00000936      488d3df00200.  lea rdi, str.Age            ; 0xc2d ; "Age?" ; const char *s
│      │    0x0000093d      e8fefcffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x00000942      8b45f4         mov eax, dword [var_ch]
│      │    0x00000945      4863d0         movsxd rdx, eax
│      │    0x00000948      4889d0         mov rax, rdx
│      │    0x0000094b      4801c0         add rax, rax
│      │    0x0000094e      4801d0         add rax, rdx
│      │    0x00000951      48c1e002       shl rax, 2
│      │    0x00000955      4889c2         mov rdx, rax
│      │    0x00000958      488b45f8       mov rax, qword [var_8h]
│      │    0x0000095c      4801d0         add rax, rdx
│      │    0x0000095f      4883c004       add rax, 4
│      │    0x00000963      4889c6         mov rsi, rax
│      │    0x00000966      488d3dc50200.  lea rdi, [0x00000c32]       ; " %i" ; const char *format
│      │    0x0000096d      b800000000     mov eax, 0
│      │    0x00000972      e809fdffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      │    0x00000977      488d3db80200.  lea rdi, str.Mark           ; 0xc36 ; "Mark?" ; const char *s
│      │    0x0000097e      e8bdfcffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x00000983      8b45f4         mov eax, dword [var_ch]
│      │    0x00000986      4863d0         movsxd rdx, eax
│      │    0x00000989      4889d0         mov rax, rdx
│      │    0x0000098c      4801c0         add rax, rax
│      │    0x0000098f      4801d0         add rax, rdx
│      │    0x00000992      48c1e002       shl rax, 2
│      │    0x00000996      4889c2         mov rdx, rax
│      │    0x00000999      488b45f8       mov rax, qword [var_8h]
│      │    0x0000099d      4801d0         add rax, rdx
│      │    0x000009a0      4883c008       add rax, 8
│      │    0x000009a4      4889c6         mov rsi, rax
│      │    0x000009a7      488d3d8e0200.  lea rdi, [0x00000c3c]       ; " %f" ; const char *format
│      │    0x000009ae      b800000000     mov eax, 0
│      │    0x000009b3      e8c8fcffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      │    0x000009b8      8b45f4         mov eax, dword [var_ch]
│      │    0x000009bb      83c001         add eax, 1
│      │    ; CODE XREF from sym.addstudents @ 0x8f4
│      └──> 0x000009be      c9             leave
└           0x000009bf      c3             ret
[0x000008b4]> 
```
That function looks a bit large compared to those in the previous tutorials but, you can easily see that it follows a pattern:
```
│      │└─> 0x000008f9      488d3d1b0300.  lea rdi, str.First_letter   ; 0xc1b ; "First letter?" ; const char *s
│      │    0x00000900      e83bfdffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x00000905      8b45f4         mov eax, dword [var_ch]
│      │    0x00000908      4863d0         movsxd rdx, eax
│      │    0x0000090b      4889d0         mov rax, rdx
│      │    0x0000090e      4801c0         add rax, rax
│      │    0x00000911      4801d0         add rax, rdx
│      │    0x00000914      48c1e002       shl rax, 2
│      │    0x00000918      4889c2         mov rdx, rax
│      │    0x0000091b      488b45f8       mov rax, qword [var_8h]
│      │    0x0000091f      4801d0         add rax, rdx
│      │    0x00000922      4889c6         mov rsi, rax
│      │    0x00000925      488d3dfd0200.  lea rdi, [0x00000c29]       ; " %c" ; const char *format
│      │    0x0000092c      b800000000     mov eax, 0
│      │    0x00000931      e84afdffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      │    0x00000936      488d3df00200.  lea rdi, str.Age            ; 0xc2d ; "Age?" ; const char *s
```
The pattern repeats three times for those three values the function asks for, letter, age, mark with one single difference. On the age block we see an extra add 0x4 and 0x8 in the case of the float block. We can easily relate those to the size of both int and float in C...

Let's first inspect the block related to the char read. If loads the value of local_ch, runs some operations on it and then it adds it to the val of local_8h. And as we can see by inspecting the top of this function and the order of the params being passed to it in sym.func1 we see that local_ch = the int related to the position on the array, local_8h the array base_addr. And what do those operations do? On this case I personally think that they are relevant as they help us better uderstand how our data is structured.

So those operations translate to this:

```
val = local_ch
val = val + val
val = val + local_ch

val = val + 2^2 (the shl 2 translates to that)

addr_char_towrite = local_8h + val
```
And as we can calculate, for an index of 0x0 the result will be 0xC (dec 12), on the next block the same operation is repeated an an extra 0x4 is added then on the final block a 0x8. so there is a distance of 0xC (dec 12) between the first and the last it all makes sense now, right? With that you can figure the whole structure out, by the way try to debug the program, add some values and dump the struct.

Now that we have "figured out" the structure of the data we can even run r2 on debug mode and dump the content like this:

```
[0x5645465e8aee]> pf 5c...df @ 0x7ffe3530d310
0x7ffe3530d310 [0] {
  0x7ffe3530d310 = 'A'
        0x7ffe3530d314 = 23
  0x7ffe3530d318 = 3.29999995
}
0x7ffe3530d31c [1] {
  0x7ffe3530d31c = 'L'
        0x7ffe3530d320 = 2
  0x7ffe3530d324 = 3.4000001
}
0x7ffe3530d328 [2] {
  0x7ffe3530d328 = 'B'
        0x7ffe3530d32c = 19
  0x7ffe3530d330 = 6.4000001
}
0x7ffe3530d334 [3] {
  0x7ffe3530d334 = 'C'
        0x7ffe3530d338 = 32
  0x7ffe3530d33c = 7.69999981
}
```

If you remind, there was another interesting function on the program... sym.showstudents but we did not see it anywhere in the code (?) Anyway for now we can also seek to it and inspect it with s
```
[0x000007c4]> pdf
┌ 240: sym.showstudents (int64_t arg1, signed int64_t arg2);
│           ; var signed int64_t var_1ch @ rbp-0x1c
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_4h @ rbp-0x4
│           ; arg int64_t arg1 @ rdi
│           ; arg signed int64_t arg2 @ rsi
│           0x000007c4      55             push rbp
│           0x000007c5      4889e5         mov rbp, rsp
│           0x000007c8      4883ec20       sub rsp, 0x20
│           0x000007cc      48897de8       mov qword [var_18h], rdi    ; arg1
│           0x000007d0      8975e4         mov dword [var_1ch], esi    ; arg2
│           0x000007d3      488d3dd20300.  lea rdi, str.Showing_students: ; 0xbac ; "Showing students: " ; const char *s
│           0x000007da      e861feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000007df      c745fc000000.  mov dword [var_4h], 0
│       ┌─< 0x000007e6      e9ba000000     jmp 0x8a5
│       │   ; CODE XREF from sym.showstudents @ 0x8ab
│      ┌──> 0x000007eb      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x000007ee      89c6           mov esi, eax
│      ╎│   0x000007f0      488d3dc80300.  lea rdi, str.Student_num__d: ; 0xbbf ; "Student num %d: " ; const char *format
│      ╎│   0x000007f7      b800000000     mov eax, 0
│      ╎│   0x000007fc      e85ffeffff     call sym.imp.printf         ; int printf(const char *format)
│      ╎│   0x00000801      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x00000804      4863d0         movsxd rdx, eax
│      ╎│   0x00000807      4889d0         mov rax, rdx
│      ╎│   0x0000080a      4801c0         add rax, rax
│      ╎│   0x0000080d      4801d0         add rax, rdx
│      ╎│   0x00000810      48c1e002       shl rax, 2
│      ╎│   0x00000814      4889c2         mov rdx, rax
│      ╎│   0x00000817      488b45e8       mov rax, qword [var_18h]
│      ╎│   0x0000081b      4801d0         add rax, rdx
│      ╎│   0x0000081e      0fb600         movzx eax, byte [rax]
│      ╎│   0x00000821      0fbec0         movsx eax, al
│      ╎│   0x00000824      89c6           mov esi, eax
│      ╎│   0x00000826      488d3da30300.  lea rdi, str.First_letter____c ; 0xbd0 ; "First letter = %c " ; const char *format
│      ╎│   0x0000082d      b800000000     mov eax, 0
│      ╎│   0x00000832      e829feffff     call sym.imp.printf         ; int printf(const char *format)
│      ╎│   0x00000837      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x0000083a      4863d0         movsxd rdx, eax
│      ╎│   0x0000083d      4889d0         mov rax, rdx
│      ╎│   0x00000840      4801c0         add rax, rax
│      ╎│   0x00000843      4801d0         add rax, rdx
│      ╎│   0x00000846      48c1e002       shl rax, 2
│      ╎│   0x0000084a      4889c2         mov rdx, rax
│      ╎│   0x0000084d      488b45e8       mov rax, qword [var_18h]
│      ╎│   0x00000851      4801d0         add rax, rdx
│      ╎│   0x00000854      8b4004         mov eax, dword [rax + 4]
│      ╎│   0x00000857      89c6           mov esi, eax
│      ╎│   0x00000859      488d3d830300.  lea rdi, str.Age____d       ; 0xbe3 ; "Age = %d " ; const char *format
│      ╎│   0x00000860      b800000000     mov eax, 0
│      ╎│   0x00000865      e8f6fdffff     call sym.imp.printf         ; int printf(const char *format)
│      ╎│   0x0000086a      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x0000086d      4863d0         movsxd rdx, eax
│      ╎│   0x00000870      4889d0         mov rax, rdx
│      ╎│   0x00000873      4801c0         add rax, rax
│      ╎│   0x00000876      4801d0         add rax, rdx
│      ╎│   0x00000879      48c1e002       shl rax, 2
│      ╎│   0x0000087d      4889c2         mov rdx, rax
│      ╎│   0x00000880      488b45e8       mov rax, qword [var_18h]
│      ╎│   0x00000884      4801d0         add rax, rdx
│      ╎│   0x00000887      f30f104008     movss xmm0, dword [rax + 8]
│      ╎│   0x0000088c      f30f5ac0       cvtss2sd xmm0, xmm0
│      ╎│   0x00000890      488d3d560300.  lea rdi, str.Mark____f      ; 0xbed ; "Mark = %f \n" ; const char *format
│      ╎│   0x00000897      b801000000     mov eax, 1
│      ╎│   0x0000089c      e8bffdffff     call sym.imp.printf         ; int printf(const char *format)
│      ╎│   0x000008a1      8345fc01       add dword [var_4h], 1
│      ╎│   ; CODE XREF from sym.showstudents @ 0x7e6
│      ╎└─> 0x000008a5      8b45fc         mov eax, dword [var_4h]
│      ╎    0x000008a8      3b45e4         cmp eax, dword [var_1ch]
│      └──< 0x000008ab      0f8c3affffff   jl 0x7eb
│           0x000008b1      90             nop
│           0x000008b2      c9             leave
└           0x000008b3      c3             ret
[0x000007c4]> 
```
As we see, the same exact pattern appears here
```
│      ╎│   0x00000801      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x00000804      4863d0         movsxd rdx, eax
│      ╎│   0x00000807      4889d0         mov rax, rdx
│      ╎│   0x0000080a      4801c0         add rax, rax
│      ╎│   0x0000080d      4801d0         add rax, rdx
│      ╎│   0x00000810      48c1e002       shl rax, 2
│      ╎│   0x00000814      4889c2         mov rdx, rax
│      ╎│   0x00000817      488b45e8       mov rax, qword [var_18h]
│      ╎│   0x0000081b      4801d0         add rax, rdx
│      ╎│   0x0000081e      0fb600         movzx eax, byte [rax]
│      ╎│   0x00000821      0fbec0         movsx eax, al
│      ╎│   0x00000824      89c6           mov esi, eax
│      ╎│   0x00000826      488d3da30300.  lea rdi, str.First_letter____c ; 0xbd0 ; "First letter = %c " ; const char *format
│      ╎│   0x0000082d      b800000000     mov eax, 0
│      ╎│   0x00000832      e829feffff     call sym.imp.printf         ; int printf(const char *format)
```
It makes a lot of sense as the function is almost exactly the same as addstudents, the main difference is that addstudents adds to memory from a pointer then this one reads from a pointer, anyway the pointer calculation is the same as well as the input parameters. Mystery solved here, it follows the same pattern to print the values of each struct.

So what happens with the showstudents function? It does not appear on the code it might have been an mistake made by the developer or maybe it is kind of a hidden feature. We can try to fix that by patching the program.

Patching an ELF binary (or whatever program) is not a trivial task, btw it may be a very complex operation as shifting and adding a single byte can mess everything up. Explaining the ELF format, mem alignments and such is beyond the scope of this single post, we will deal with that later on. Just note that the program has a fixed size on disk and a structure, right? If we want to add more code = more instructions to it, like a call to sym.showstudents we have two options being a) to overwrite some of the existing space (probably overwriting instructions) on the, for example, the .text section (section marked as executable) or b) increase the file size, add the code and realign everything. We'll go with the first option right now and we'll dig deeper on the second one later on (if you want to get more info related on this second option check this: http://phrack.org/issues/66/14.html).

So we'll go by the first option. We will over write existing space (instructions) on the program to call the showstudents function.

After examining the code, we see that sym.addstudents function gets called here:

```
│     │╎│   0x00000ae4      89d6           mov esi, edx                ; signed int64_t arg2
│     │╎│   0x00000ae6      4889c7         mov rdi, rax                ; int64_t arg1
│     │╎│   0x00000ae9      e8c6fdffff     call sym.addstudents
│     │╎│   0x00000aee      8945d4         mov dword [var_2ch], eax
│     │╎│   ; CODE XREFS from sym.func1 @ 0xaaf, 0xadb
```
The context around this call is perfect for us, as both the base addr and the counter are being loaded as parameters it would be very nice to add a call to showstudents right before the addstudents call, but we can't do it without "breaking" the prrogram. And we cannot overwrite any instruction there as all of them are relevant...

But... let's look inside showstudents again...
```
│           0x000007cc      48897de8       mov qword [var_18h], rdi    ; arg1
│           0x000007d0      8975e4         mov dword [var_1ch], esi    ; arg2
│           0x000007d3      488d3dd20300.  lea rdi, str.Showing_students: ; 0xbac ; "Showing students: " ; const char *s
│           0x000007da      e861feffff     call sym.imp.puts           ; int puts(const char *s)
```
We see a printf there that is far from necessary, so we can overwrite it with a call to addstudents, so before showing the users the program will let us add a new one!

After overwriting there, we can also overwrite the call in sym.func1 with a call to showstudents. If we do that we'll also have to update the mov dword var_2ch, eax as showstudents does not return anything we can change that mov with an inc

So in r2 paching can be made with wa. With s we seek to the addr where we wanna update, and with wa we assamble a new instruction. Remember that we will need to open the program with the write option enabled (r2 -wA program) to edit it.

```
$ r2 -wA struct1
[0x0000138b]> s 0x000014b8
[0x000014b8]> wa inc [ebp-0x2c]

│     │╎│   0x00000ae6      4889c7         mov rdi, rax                ; int64_t arg1
│     │╎│   0x00000ae9      e8c6fdffff     call sym.addstudents
│     │╎│   0x00000aee      ff45d4         inc dword [var_2ch]
│     │╎│   ; CODE XREFS from sym.func1 @ 0xaaf, 0xadb
│     └─└─> 0x00000af1      0fb645d3       movzx eax, byte [var_2dh]


[0x0000118f]> s 0x000011a5
[0x000011a5]> wa call sym.addstudents
Written 5 byte(s) (call sym.addstudents) = wx e8d5000000


[0x000011a5]> s 0x0000119e
[0x0000119e]> wa nop
Written 1 byte(s) (nop) = wx 90

[0x0000118f]> s 0x0000119f
[0x0000119f]> wa nop

│           0x000007d3      90             nop
│           0x000007d4      90             nop
│           0x000007d5      3dd2030000     cmp eax, 0x3d2              ; "9_scanf"
│           0x000007da      e8d5000000     call sym.addstudents
│           0x000007df      c745fc000000.  mov dword [var_4h], 0


[0x0000138b]> s 0x000014b3
[0x000014b3]> wa call sym.showstudents
Written 5 byte(s) (call sym.showstudents) = wx e8d7fcffff


│     │╎│   0x00000ae6      4889c7         mov rdi, rax                ; int64_t arg1
│     │╎│   0x00000ae9      e8d6fcffff     call sym.showstudents
│     │╎│   0x00000aee      ff45d4         inc dword [var_2ch]
│     │╎│   ; CODE XREFS from sym.func1 @ 0xaaf, 0xadb
```

```
First letter?
X
Age?
34
Mark?
4.6
Student num 0: First letter = P Age = 23 Mark = 3.400000 
Student num 1: First letter = k Age = 3 Mark = 4.000000 
Action? (q=Quit, a=Add, s=ShowAll)
```

So we are done for now. We'll go deeper into binary modification/patching on the following posts. Thanks for reading.
![honestwork](https://preview.redd.it/fm2cxaptrt821.jpg?width=960&crop=smart&auto=webp&s=9a66e4744cb3f6fe08ebc81af694eeb4dcbadefd"work")

