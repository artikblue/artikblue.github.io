

OPEN FILE AND READ

#include <stdio.h>
#include <string.h>
main(){
funcion();
getchar();
}


funcion()
{ 

    FILE* ftest;
    char name[80] = "test.txt";
    char line[81];
 
    ftest = fopen(name, "rt");
 
    if (ftest == NULL)
    {
      printf("file not found!\n");
      exit(1);
    }
    fgets(line, 80, ftest);
    puts(line);
fgets(line, 80, ftest);
    puts(line);
    fclose(ftest);


}






OPEN FILE

│           0x55d1449c31c9      48b874657374.  movabs rax, 0x7478742e74736574 ; 'test.txt'
│           0x55d1449c31d3      ba00000000     mov edx, 0
│           0x55d1449c31d8      48898550ffff.  mov qword [var_b0h], rax
│           0x55d1449c31df      48899558ffff.  mov qword [var_a8h], rdx
│           0x55d1449c31e6      48c78560ffff.  mov qword [var_a0h], 0
│           0x55d1449c31f1      48c78568ffff.  mov qword [var_98h], 0
│           0x55d1449c31fc      48c78570ffff.  mov qword [var_90h], 0
│           0x55d1449c3207      48c78578ffff.  mov qword [var_88h], 0
│           0x55d1449c3212      48c745800000.  mov qword [var_80h], 0
│           0x55d1449c321a      48c745880000.  mov qword [var_78h], 0
│           0x55d1449c3222      48c745900000.  mov qword [var_70h], 0
│           0x55d1449c322a      48c745980000.  mov qword [var_68h], 0
│           0x55d1449c3232      488d8550ffff.  lea rax, [var_b0h]
│           0x55d1449c3239      488d35c40d00.  lea rsi, [0x55d1449c4004] ; "rt"
│           0x55d1449c3240      4889c7         mov rdi, rax
│           0x55d1449c3243      e838feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           0x55d1449c3248 b    48898548ffff.  mov qword [var_b8h], rax
│           0x55d1449c324f      4883bd48ffff.  cmp qword [var_b8h], 0
│       ┌─< 0x55d1449c3257      7516           jne 0x55d1449c326f


CHECK IF FILE OPENED CORRECTLY

│       ┌─< 0x55d1449c3257      7516           jne 0x55d1449c326f
│       │   0x55d1449c3259      488d3da70d00.  lea rdi, str.file_not_found ; 0x55d1449c4007 ; "file not found!"
│       │   0x55d1449c3260      e8cbfdffff     call sym.imp.puts       ; int puts(const char *s)
│       │   0x55d1449c3265      bf01000000     mov edi, 1
│       │   0x55d1449c326a      e821feffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x55d1449c326f      488b9548ffff.  mov rdx, qword [var_b8h]


FILE POINTER

│           0x55d1449c3240      4889c7         mov rdi, rax
│           0x55d1449c3243      e838feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           ;-- rip:
│           0x55d1449c3248 b    48898548ffff.  mov qword [var_b8h], rax
│           0x55d1449c324f      4883bd48ffff.  cmp qword [var_b8h], 0


FILE POINTER IN MEMORY

[0x55d1449c3248]> dr
rax = 0x55d145eef260
rbx = 0x00000000
rcx = 0x00000005
rdx = 0x00000000
r8 = 0x00000000
r9 = 0x55d1449c4006
r10 = 0x00000000
r11 = 0x00000246
r12 = 0x55d1449c30b0
r13 = 0x7ffc18e1dc20
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x00000000
rdi = 0x55d1449c4005
rsp = 0x7ffc18e1da70
rbp = 0x7ffc18e1db30
rip = 0x55d1449c3248
rflags = 0x00000206
orax = 0xffffffffffffffff
[0x55d1449c3248]> pxw @ 0x55d145eef260
0x55d145eef260  0xfbad2488 0x00000000 0x00000000 0x00000000  .$..............
0x55d145eef270  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef280  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef290  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef2a0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef2b0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef2c0  0x00000000 0x00000000 0xf2630680 0x00007f28  ..........c.(...
0x55d145eef2d0  0x00000003 0x00000000 0x00000000 0x00000000  ................
0x55d145eef2e0  0x00000000 0x00000000 0x45eef340 0x000055d1  ........@..E.U..
0x55d145eef2f0  0xffffffff 0xffffffff 0x00000000 0x00000000  ................
0x55d145eef300  0x45eef350 0x000055d1 0x00000000 0x00000000  P..E.U..........
0x55d145eef310  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef320  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x55d145eef330  0x00000000 0x00000000 0xf2631560 0x00007f28  ........`.c.(...
0x55d145eef340  0x00000000 0x00000000 0x00000000 0x00000000  ................




[0x55d1449c3282]> dr
rax = 0x7ffc18e1dad0
rbx = 0x00000000
rcx = 0x00000005
rdx = 0x55d145eef260
r8 = 0x00000000
r9 = 0x55d1449c4006
r10 = 0x00000000
r11 = 0x00000246
r12 = 0x55d1449c30b0
r13 = 0x7ffc18e1dc20
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x00000050
rdi = 0x7ffc18e1dad0
rsp = 0x7ffc18e1da70
rbp = 0x7ffc18e1db30
rip = 0x55d1449c3282
rflags = 0x00000206
orax = 0xffffffffffffffff
[0x55d1449c3282]> pxw @ 0x7ffc18e1dad0
0x7ffc18e1dad0  0x00000000 0x00000000 0x00f0b5ff 0x00000000  ................
0x7ffc18e1dae0  0x000000c2 0x00000000 0x18e1db16 0x00007ffc  ................
0x7ffc18e1daf0  0x00000001 0x00000000 0xf2505b55 0x00007f28  ........U[P.(...
0x7ffc18e1db00  0x00000000 0x00000000 0x449c3325 0x000055d1  ........%3.D.U..
0x7ffc18e1db10  0xf2661b20 0x00007f28 0x00000000 0x00000000   .f.(...........
0x7ffc18e1db20  0x449c32e0 0x000055d1 0xb67e8600 0x110eefa4  .2.D.U....~.....
0x7ffc18e1db30  0x18e1db40 0x00007ffc 0x449c31a3 0x000055d1  @........1.D.U..
0x7ffc18e1db40  0x449c32e0 0x000055d1 0xf2471b6b 0x00007f28  .2.D.U..k.G.(...
0x7ffc18e1db50  0x00000000 0x00000000 0x18e1dc28 0x00007ffc  ........(.......
0x7ffc18e1db60  0x00040000 0x00000001 0x449c3195 0x000055d1  .........1.D.U..
0x7ffc18e1db70  0x00000000 0x00000000 0xdb1818b4 0xd55ddb37  ............7.].
0x7ffc18e1db80  0x449c30b0 0x000055d1 0x18e1dc20 0x00007ffc  .0.D.U.. .......
0x7ffc18e1db90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dba0  0x087818b4 0x810763cc 0x889e18b4 0x80aeb681  ..x..c..........
0x7ffc18e1dbb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dbc0  0x00000000 0x00000000 0x18e1dc38 0x00007ffc  ........8.......
[0x55d1449c3282]> dc
hit breakpoint at: 55d1449c3287
[0x55d1449c3287]> pxw @ 0x7ffc18e1dad0
0x7ffc18e1dad0  0x4c4c4548 0x4c45484f 0x45484f4c 0x0a4f4c4c  HELLOHELLOHELLO.
0x7ffc18e1dae0  0x00000000 0x00000000 0x18e1db16 0x00007ffc  ................
0x7ffc18e1daf0  0x00000001 0x00000000 0xf2505b55 0x00007f28  ........U[P.(...
0x7ffc18e1db00  0x00000000 0x00000000 0x449c3325 0x000055d1  ........%3.D.U..
0x7ffc18e1db10  0xf2661b20 0x00007f28 0x00000000 0x00000000   .f.(...........
0x7ffc18e1db20  0x449c32e0 0x000055d1 0xb67e8600 0x110eefa4  .2.D.U....~.....
0x7ffc18e1db30  0x18e1db40 0x00007ffc 0x449c31a3 0x000055d1  @........1.D.U..
0x7ffc18e1db40  0x449c32e0 0x000055d1 0xf2471b6b 0x00007f28  .2.D.U..k.G.(...
0x7ffc18e1db50  0x00000000 0x00000000 0x18e1dc28 0x00007ffc  ........(.......
0x7ffc18e1db60  0x00040000 0x00000001 0x449c3195 0x000055d1  .........1.D.U..
0x7ffc18e1db70  0x00000000 0x00000000 0xdb1818b4 0xd55ddb37  ............7.].
0x7ffc18e1db80  0x449c30b0 0x000055d1 0x18e1dc20 0x00007ffc  .0.D.U.. .......
0x7ffc18e1db90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dba0  0x087818b4 0x810763cc 0x889e18b4 0x80aeb681  ..x..c..........
0x7ffc18e1dbb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dbc0  0x00000000 0x00000000 0x18e1dc38 0x00007ffc  ........8.......
[0x55d1449c3287]> 


SECOND FGETS


│           ;-- rip:
│           0x55d1449c32a6 b    e8b5fdffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
│           0x55d1449c32ab      488d45a0       lea rax, [var_60h]
│           0x55d1449c32af      4889c7         mov rdi, rax
│           0x55d1449c32b2      e879fdffff     call sym.imp.puts       ; int puts(const char *s)
│           0x55d1449c32b7      488b8548ffff.  mov rax, qword [var_b8h]
│           0x55d1449c32be      4889c7         mov rdi, rax
│           0x55d1449c32c1      e87afdffff     call sym.imp.fclose     ; int fclose(FILE *stream)
│           0x55d1449c32c6      90             nop
│           0x55d1449c32c7      488b4df8       mov rcx, qword [var_8h]
│           0x55d1449c32cb      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x55d1449c32d4      7405           je 0x55d1449c32db
│       │   0x55d1449c32d6      e875fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55d1449c32db      c9             leave
└           0x55d1449c32dc      c3             ret
[0x55d1449c32a6]> db 0x55d1449c32ab
[0x55d1449c32a6]> pxw @ 0x7ffc18e1dad0
0x7ffc18e1dad0  0x4c4c4548 0x4c45484f 0x45484f4c 0x0a4f4c4c  HELLOHELLOHELLO.
0x7ffc18e1dae0  0x00000000 0x00000000 0x18e1db16 0x00007ffc  ................
0x7ffc18e1daf0  0x00000001 0x00000000 0xf2505b55 0x00007f28  ........U[P.(...
0x7ffc18e1db00  0x00000000 0x00000000 0x449c3325 0x000055d1  ........%3.D.U..
0x7ffc18e1db10  0xf2661b20 0x00007f28 0x00000000 0x00000000   .f.(...........
0x7ffc18e1db20  0x449c32e0 0x000055d1 0xb67e8600 0x110eefa4  .2.D.U....~.....
0x7ffc18e1db30  0x18e1db40 0x00007ffc 0x449c31a3 0x000055d1  @........1.D.U..
0x7ffc18e1db40  0x449c32e0 0x000055d1 0xf2471b6b 0x00007f28  .2.D.U..k.G.(...
0x7ffc18e1db50  0x00000000 0x00000000 0x18e1dc28 0x00007ffc  ........(.......
0x7ffc18e1db60  0x00040000 0x00000001 0x449c3195 0x000055d1  .........1.D.U..
0x7ffc18e1db70  0x00000000 0x00000000 0xdb1818b4 0xd55ddb37  ............7.].
0x7ffc18e1db80  0x449c30b0 0x000055d1 0x18e1dc20 0x00007ffc  .0.D.U.. .......
0x7ffc18e1db90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dba0  0x087818b4 0x810763cc 0x889e18b4 0x80aeb681  ..x..c..........
0x7ffc18e1dbb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dbc0  0x00000000 0x00000000 0x18e1dc38 0x00007ffc  ........8.......
[0x55d1449c32a6]> dc
hit breakpoint at: 55d1449c32ab
[0x55d1449c32ab]> pxw @ 0x7ffc18e1dad0
0x7ffc18e1dad0  0x4c524f57 0x524f5744 0x4f57444c 0x0a444c52  WORLDWORLDWORLD.
0x7ffc18e1dae0  0x00000000 0x00000000 0x18e1db16 0x00007ffc  ................
0x7ffc18e1daf0  0x00000001 0x00000000 0xf2505b55 0x00007f28  ........U[P.(...
0x7ffc18e1db00  0x00000000 0x00000000 0x449c3325 0x000055d1  ........%3.D.U..
0x7ffc18e1db10  0xf2661b20 0x00007f28 0x00000000 0x00000000   .f.(...........
0x7ffc18e1db20  0x449c32e0 0x000055d1 0xb67e8600 0x110eefa4  .2.D.U....~.....
0x7ffc18e1db30  0x18e1db40 0x00007ffc 0x449c31a3 0x000055d1  @........1.D.U..
0x7ffc18e1db40  0x449c32e0 0x000055d1 0xf2471b6b 0x00007f28  .2.D.U..k.G.(...
0x7ffc18e1db50  0x00000000 0x00000000 0x18e1dc28 0x00007ffc  ........(.......
0x7ffc18e1db60  0x00040000 0x00000001 0x449c3195 0x000055d1  .........1.D.U..
0x7ffc18e1db70  0x00000000 0x00000000 0xdb1818b4 0xd55ddb37  ............7.].
0x7ffc18e1db80  0x449c30b0 0x000055d1 0x18e1dc20 0x00007ffc  .0.D.U.. .......
0x7ffc18e1db90  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dba0  0x087818b4 0x810763cc 0x889e18b4 0x80aeb681  ..x..c..........
0x7ffc18e1dbb0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffc18e1dbc0  0x00000000 0x00000000 0x18e1dc38 0x00007ffc  ........8.......
[0x55d1449c32ab]> 

-------------------------------------
























SEEK

[0x7f376be20090]> s main
[0x560d0969d165]> pdf
            ; DATA XREF from entry0 @ 0x560d0969d09d
┌ 130: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           0x560d0969d165      55             push rbp
│           0x560d0969d166      4889e5         mov rbp, rsp
│           0x560d0969d169      4883ec10       sub rsp, 0x10
│           0x560d0969d16d      488d35940e00.  lea rsi, [0x560d0969e008] ; "w+"
│           0x560d0969d174      488d3d900e00.  lea rdi, str.fseek.txt  ; 0x560d0969e00b ; "fseek.txt"
│           0x560d0969d17b      e8d0feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           0x560d0969d180      488945f8       mov qword [var_8h], rax
│           0x560d0969d184      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d188      4889c1         mov rcx, rax
│           0x560d0969d18b      ba51000000     mov edx, 0x51           ; 'Q' ; 81
│           0x560d0969d190      be01000000     mov esi, 1
│           0x560d0969d195      488d3d7c0e00.  lea rdi, str.This_is_a_simple_file__feel_free_to_visit_artik.blue_to_get_fresh_reversing_stuff ; 0x560d0969e018 ; "This is a simple file, feel free to visit artik.blue to get fresh reversing stuff"
│           0x560d0969d19c      e8bffeffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x560d0969d1a1      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1a5      ba00000000     mov edx, 0
│           0x560d0969d1aa      be07000000     mov esi, 7
│           0x560d0969d1af      4889c7         mov rdi, rax
│           0x560d0969d1b2      e889feffff     call sym.imp.fseek      ; int fseek(FILE *stream, long offset, int whence)
│           0x560d0969d1b7      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1bb      4889c1         mov rcx, rax
│           0x560d0969d1be      ba17000000     mov edx, 0x17           ; 23
│           0x560d0969d1c3      be01000000     mov esi, 1
│           0x560d0969d1c8      488d3d9b0e00.  lea rdi, str.C_Programming_Language ; 0x560d0969e06a ; " C Programming Language"
│           0x560d0969d1cf      e88cfeffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x560d0969d1d4      488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1d8      4889c7         mov rdi, rax
│           0x560d0969d1db      e850feffff     call sym.imp.fclose     ; int fclose(FILE *stream)
│           0x560d0969d1e0      b800000000     mov eax, 0
│           0x560d0969d1e5      c9             leave
└           0x560d0969d1e6      c3             ret
[0x560d0969d165]> 


[0x560d0969d180]> dr
rax = 0x560d0a3ca260
rbx = 0x00000000
rcx = 0x0000000a
rdx = 0x00000000
r8 = 0x00000240
r9 = 0x560d0969e00a
r10 = 0x000001b6
r11 = 0x00000246
r12 = 0x560d0969d080
r13 = 0x7fff257b3500
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x00000000
rdi = 0x560d0969e00a
rsp = 0x7fff257b3410
rbp = 0x7fff257b3420
rip = 0x560d0969d180
rflags = 0x00000206
orax = 0xffffffffffffffff
[0x560d0969d180]> pxw @ 0x560d0a3ca260
0x560d0a3ca260  0xfbad2480 0x00000000 0x00000000 0x00000000  .$..............
0x560d0a3ca270  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x560d0a3ca280  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x560d0a3ca290  0x00000000 0x00000000 0x00000000 0x00000000  ................



│           0x560d0969d195      488d3d7c0e00.  lea rdi, str.This_is_a_simple_file__feel_free_to_visit_artik.blue_to_get_fresh_reversing_stuff ; 0x560d0969e018 ; "This is a simple file, feel free to visit artik.blue to get fresh reversing stuff"
│           0x560d0969d19c b    e8bffeffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           ;-- rip:
│           0x560d0969d1a1 b    488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1a5      ba00000000     mov edx, 0
│           0x560d0969d1aa      be07000000     mov esi, 7
│           0x560d0969d1af      4889c7         mov rdi, rax



[0x560d0969d1a1]> dr
rax = 0x00000051
rbx = 0x00000000
rcx = 0x00001000
rdx = 0x00000051
r8 = 0x00000000
r9 = 0x00000063
r10 = 0x7f376bdfdca0
r11 = 0x7f376bdfdca0
r12 = 0x560d0969d080
r13 = 0x7fff257b3500
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x560d0a3ca340
rdi = 0x560d0a3ca490
rsp = 0x7fff257b3410
rbp = 0x7fff257b3420
rip = 0x560d0969d1a1
rflags = 0x00000206
orax = 0xffffffffffffffff

This is a simple file, feel free to visit artik.blue to get fresh reversing stuff = 81 characters 0x51 = dec 81


│           ;-- rip:
│           0x560d0969d1a1 b    488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1a5      ba00000000     mov edx, 0
│           0x560d0969d1aa      be07000000     mov esi, 7
│           0x560d0969d1af      4889c7         mov rdi, rax
│           0x560d0969d1b2 b    e889feffff     call sym.imp.fseek      ; int fseek(FILE *stream, long offset, int whence)
│           0x560d0969d1b7 b    488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1bb      4889c1         mov rcx, rax

0x7 we are seeking to char array [7] pos


│           0x560d0969d19c b    e8bffeffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x560d0969d1a1 b    488b45f8       mov rax, qword [var_8h]
│           ;-- rip:
│           0x560d0969d1a5      ba00000000     mov edx, 0
│           0x560d0969d1aa      be07000000     mov esi, 7
│           0x560d0969d1af      4889c7         mov rdi, rax

var_8h = file pointer

|           0x560d0969d1a5      ba00000000     mov edx, 0
│           0x560d0969d1aa      be07000000     mov esi, 7
│           0x560d0969d1af      4889c7         mov rdi, rax
│           0x560d0969d1b2 b    e889feffff     call sym.imp.fseek      ; int fseek(FILE *stream, long offset, int whence)

***** WATCH OUT

before the fseek call

[0x560d0969d1b2]> pxw @ 0x560d0a3ca260
0x560d0a3ca260  0xfbad2c80 0x00000000 0x0a3ca490 0x0000560d  .,........<..V..
0x560d0a3ca270  0x0a3ca490 0x0000560d 0x0a3ca490 0x0000560d  ..<..V....<..V..
0x560d0a3ca280  0x0a3ca490 0x0000560d 0x0a3ca4e1 0x0000560d  ..<..V....<..V..


after the fseek calll

[0x560d0969d1b7]> pxw @ 0x560d0a3ca260
0x560d0a3ca260  0xfbad2480 0x00000000 0x0a3ca497 0x0000560d  .$........<..V..
0x560d0a3ca270  0x0a3ca4e1 0x0000560d 0x0a3ca490 0x0000560d  ..<..V....<..V..


│           0x560d0969d1b7 b    488b45f8       mov rax, qword [var_8h]
│           0x560d0969d1bb      4889c1         mov rcx, rax
│           0x560d0969d1be      ba17000000     mov edx, 0x17           ; 23
│           0x560d0969d1c3      be01000000     mov esi, 1
│           0x560d0969d1c8      488d3d9b0e00.  lea rdi, str.C_Programming_Language ; 0x560d0969e06a ; " C Programming Language"
│           0x560d0969d1cf b    e88cfeffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)










----------------------------------


#include <stdio.h>


void main(){
char buffer[500];
FILE *fp;
int lineno = 0;
if ((fp = fopen("myinputfile.txt","r")) == NULL)
{
        printf("Could not open myinputfile.txt\n");
        exit(1);
}

while ( !feof(fp))
{
        // read in the line and make sure it was successful
        if (fgets(buffer,500,fp) != NULL)
        {
                printf("%d: %s",lineno++,buffer);
        }
}
}




[0x55651c3ee195]> pdf
            ; DATA XREF from entry0 @ 0x55651c3ee0cd
┌ 209: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20ch @ rbp-0x20c
│           ; var int64_t var_208h @ rbp-0x208
│           ; var int64_t var_200h @ rbp-0x200
│           ; var int64_t var_8h @ rbp-0x8
│           0x55651c3ee195      55             push rbp
│           0x55651c3ee196      4889e5         mov rbp, rsp
│           0x55651c3ee199      4881ec100200.  sub rsp, 0x210
│           0x55651c3ee1a0      64488b042528.  mov rax, qword fs:[0x28]
│           0x55651c3ee1a9      488945f8       mov qword [var_8h], rax
│           0x55651c3ee1ad      31c0           xor eax, eax
│           0x55651c3ee1af      c785f4fdffff.  mov dword [var_20ch], 0
│           0x55651c3ee1b9      488d35480e00.  lea rsi, [0x55651c3ef008] ; "r"
│           0x55651c3ee1c0      488d3d430e00.  lea rdi, str.myinputfile.txt ; 0x55651c3ef00a ; "myinputfile.txt"
│           0x55651c3ee1c7      e8b4feffff     call sym.imp.fopen      ; file*fopen(const char *filename, const char *mode)
│           0x55651c3ee1cc      488985f8fdff.  mov qword [var_208h], rax
│           0x55651c3ee1d3      4883bdf8fdff.  cmp qword [var_208h], 0
│       ┌─< 0x55651c3ee1db      755f           jne 0x55651c3ee23c
│       │   0x55651c3ee1dd      488d3d3c0e00.  lea rdi, str.Could_not_open_myinputfile.txt ; 0x55651c3ef020 ; "Could not open myinputfile.txt"
│       │   0x55651c3ee1e4      e847feffff     call sym.imp.puts       ; int puts(const char *s)
│       │   0x55651c3ee1e9      bf01000000     mov edi, 1
│       │   0x55651c3ee1ee      e89dfeffff     call sym.imp.exit       ; void exit(int status)
│      ┌──> 0x55651c3ee1f3      488b95f8fdff.  mov rdx, qword [var_208h]
│      ╎│   0x55651c3ee1fa      488d8500feff.  lea rax, [var_200h]
│      ╎│   0x55651c3ee201      bef4010000     mov esi, 0x1f4          ; 500
│      ╎│   0x55651c3ee206      4889c7         mov rdi, rax
│      ╎│   0x55651c3ee209      e852feffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
│      ╎│   0x55651c3ee20e      4885c0         test rax, rax
│     ┌───< 0x55651c3ee211      7429           je 0x55651c3ee23c
│     │╎│   0x55651c3ee213      8b85f4fdffff   mov eax, dword [var_20ch]
│     │╎│   0x55651c3ee219      8d5001         lea edx, [rax + 1]
│     │╎│   0x55651c3ee21c      8995f4fdffff   mov dword [var_20ch], edx
│     │╎│   0x55651c3ee222      488d9500feff.  lea rdx, [var_200h]
│     │╎│   0x55651c3ee229      89c6           mov esi, eax
│     │╎│   0x55651c3ee22b      488d3d0d0e00.  lea rdi, str.d:__s      ; 0x55651c3ef03f ; "%d: %s"
│     │╎│   0x55651c3ee232      b800000000     mov eax, 0
│     │╎│   0x55651c3ee237      e814feffff     call sym.imp.printf     ; int printf(const char *format)
│     └─└─> 0x55651c3ee23c      488b85f8fdff.  mov rax, qword [var_208h]
│      ╎    0x55651c3ee243      4889c7         mov rdi, rax
│      ╎    0x55651c3ee246      e825feffff     call sym.imp.feof       ; int feof(FILE *stream)
│      ╎    0x55651c3ee24b      85c0           test eax, eax
│      └──< 0x55651c3ee24d      74a4           je 0x55651c3ee1f3
│           0x55651c3ee24f      90             nop
│           0x55651c3ee250      488b45f8       mov rax, qword [var_8h]
│           0x55651c3ee254      644833042528.  xor rax, qword fs:[0x28]
│       ┌─< 0x55651c3ee25d      7405           je 0x55651c3ee264
│       │   0x55651c3ee25f      e8dcfdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55651c3ee264      c9             leave
└           0x55651c3ee265      c3             ret
[0x55651c3ee195]> 



the comparision happens here:

│      ╎    0x55651c3ee246      e825feffff     call sym.imp.feof       ; int feof(FILE *stream)
│      ╎    0x55651c3ee24b      85c0           test eax, eax
│      └──< 0x55651c3ee24d      74a4           je 0x55651c3ee1f3




#include <stdint.h>
 
int32_t main (void) {
    int64_t var_20ch;
    int64_t var_208h;
    int64_t var_200h;
    int64_t var_8h;
    rax = *(fs:0x28);
    var_8h = *(fs:0x28);
    eax = 0;
    var_20ch = 0;
    rax = fopen ("myinputfile.txt", 0x55651c3ef008);
    var_208h = rax;
    if (var_208h != 0) {
        goto label_0;
    }
    puts ("Could not open myinputfile.txt");
    exit (1);
    do {
        rax = &var_200h;
        rax = fgets (rax, 0x1f4, var_208h);
        if (rax != 0) {
            eax = var_20ch;
            edx = rax + 1;
            var_20ch = edx;
            rdx = &var_200h;
            esi = eax;
            eax = 0;
            printf ("%d: %s");
        }
label_0:
        rax = var_208h;
        eax = feof (var_208h);
    } while (eax == 0);
    rax = var_8h;
    rax ^= *(fs:0x28);
    if (eax != 0) {
        stack_chk_fail ();
    }
    return rax;
}















#include <stdio.h>

int main () {
   FILE *fp;

   fp = fopen("fseek.txt","w+");
   fputs("This is a simple file, feel free to visit artik.blue to get fresh reversing stuff", fp);
  
   fseek( fp, 7, SEEK_SET );
   fputs(" C Programming Language", fp);
   fclose(fp);
   
   return(0);
}

