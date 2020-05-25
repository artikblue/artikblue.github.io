---
layout: post
title:  "Reverse engineering x64 binaries with Radare2 - 15 (Windows fundamentals: Intro to WinApi and file management)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_15.png
featured_image: assets/images/radare2/radare2_15.png
---


#### WindowsAPI HelloWorld

The first program is always hello wowrld. ***to be updated
```c
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int main()
{
    int msgboxID = MessageBox(NULL, "Hello dear user", "Artikblue's magic msgbox", MB_ICONWARNING | MB_CANCELTRYCONTINUE);

    switch (msgboxID)
    {
    case IDCANCEL:
        printf("CANCELING");
        Beep( 750, 300 );

        break;
    case IDTRYAGAIN:
        printf("Shall we try again?");
        Beep( 250, 100 );
        break;
    case IDCONTINUE:
        printf("The show must go on");
        Beep( 950, 500 );
        break;
    }
    return 0;
}
```
The information related to this MessageBox call can be found here: https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox

Let us first list the detected functions by using afl
```
[0x77953840]> afl
0x00401000    1 1            sym.__mingw_invalidParameterHandler
0x00401010   14 273  -> 266  sym.pre_c_init
0x00401130    1 73           sym.pre_cpp_init
0x00401180   44 850  -> 809  sym.__tmainCRTStartup
0x004014e0    1 34           entry0
0x00401510    1 25           sym.atexit
0x00401530    1 12           sym.__gcc_register_frame
0x00401540    1 1            sym.__gcc_deregister_frame
0x00401550    7 177          sym.main
0x00401610    3 53           sym.__do_global_dtors
0x00401650    9 102  -> 99   sym.__do_global_ctors
0x004016c0    3 31   -> 26   sym.__main
0x004016e0    1 7            sym.my_lconv_init
0x004016f0    1 3            sym._setargv
0x00401700    6 214  -> 206  sym.__security_init_cookie
0x004017e0    4 248          sym.__report_gsfailure
0x004018e0    4 47   -> 38   sym.__dyn_tls_dtor
0x00401910   11 115  -> 113  sym.__dyn_tls_init
0x00401990    1 3            sym.__tlregdtor
0x004019a0    3 65           sym.__mingw_raise_matherr
0x004019f0    1 12   -> 18   sym.__mingw_setusermatherr
0x00401a00    2 49           sym._matherr
0x00401a38    1 96           loc.00401a38
0x00401b00    1 3            sym._fpreset
0x00401b10    1 4            sym._decode_pointer
0x00401b20    1 4            sym._encode_pointer
0x00401b30   26 464          sym.__write_memory.part.0
0x00401d00   66 1120 -> 1076 sym._pei386_runtime_relocator
0x00402160   12 236  -> 232  sym.__mingw_init_ehandler
0x00402250   36 487  -> 458  sym._gnu_exception_handler
0x00402440    7 106          sym.__mingwthr_run_key_dtors.part.0
0x004024b0    5 127          sym.___w64_mingwthr_add_key_dtor
0x00402530   13 160  -> 141  sym.___w64_mingwthr_remove_key_dtor
0x004025d0   17 218  -> 205  sym.__mingw_TLScallback
0x004026b0    3 30           sym._ValidateImageBase.part.0
0x004026d0    3 18   -> 12   sym._ValidateImageBase
0x004026f0    7 68           sym._FindPESection
0x00402740    9 141  -> 139  sym._FindPESectionByName
0x004027d0    9 116          sym.__mingw_GetSectionForAddress
0x00402850    4 62   -> 59   sym.__mingw_GetSectionCount
0x00402890   10 111          sym._FindPESectionExec
0x00402900    3 55   -> 49   sym._GetPEImageBase
0x00402940   10 145  -> 142  sym._IsNonwritableInCurrentImage
0x004029e0   16 166  -> 162  sym.__mingw_enum_import_library_names
0x00402a90    3 50           fcn.00402a90
0x00402ad0    1 6            sym.vfprintf
0x00402ad8    1 6            sym.strncmp
0x00402ae0    1 6            sym.strlen
0x00402ae8    1 6            sym.signal
0x00402af0    1 6            sym.printf
0x00402af8    1 6            sym.memcpy
0x00402b00    1 6            sym.malloc
0x00402b08    1 6            sym.fwrite
0x00402b10    1 6            sym.free
0x00402b18    1 6            sym.fprintf
0x00402b20    1 6            sym.exit
0x00402b28    1 6            sym.calloc
0x00402b30    1 6            sym.abort
0x00402b38    1 6            sym._onexit
0x00402b40    1 6            sym._initterm
0x00402b48    1 6            sym._cexit
0x00402b50    1 6            sym._amsg_exit
0x00402b58    1 6            sym.__setusermatherr
0x00402b60    1 6            sym.__set_app_type
0x00402b70    1 6            sym.__getmainargs
0x00402b80    1 31           sym.__acrt_iob_func
0x00402ba0    1 8            sym.mingw_get_invalid_parameter_handler
0x00402bb0    1 11           sym.mingw_set_invalid_parameter_handler
0x00402bc0    1 11           sym.__p__acmdln
0x00402bd0    1 11           sym.__p__fmode
0x00402be0    1 6            sym.__iob_func
0x00402cc0    1 117          sym.__report_error
[0x77953840]>
```
Note the first difference we see here when comparing this with our previous Linux tutorial. As you can see, we see A LOT of functions here being used almost all of them not directly used, related to the windows api

It is clear that those funcs are being used by our MessageBox call

As usual in these tutorials, the program is defined inside the main function:
```
[0x004015a5]> pdf
/ (fcn) sym.main 177
|   sym.main ();
|           ; var int local_4h @ rbp-0x4
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401550      55             push rbp
|           0x00401551      4889e5         mov rbp, rsp
|           0x00401554      4883ec30       sub rsp, 0x30               ; '0'
|           0x00401558      e863010000     call sym.__main
|           0x0040155d      41b936000000   mov r9d, 0x36               ; '6' ; 54
|           0x00401563      4c8d05962a00.  lea r8, str.Artikblue_s_magic_msgbox ; section..rdata ; 0x404000 ; "Artikblue's m
|           0x0040156a      488d15a82a00.  lea rdx, str.Hello_dear_user ; 0x404019 ; "Hello dear user"
|           0x00401571      b900000000     mov ecx, 0
|           0x00401576      488b05236e00.  mov rax, qword sym.imp.USER32.dll_MessageBoxA ; [0x4083a0:8]=0x77751304
|           0x0040157d      ffd0           call rax
|           0x0040157f      8945fc         mov dword [local_4h], eax
|           0x00401582      837dfc0a       cmp dword [local_4h], 0xa   ; [0xa:4]=-1 ; 10
|       ,=< 0x00401586      742d           je 0x4015b5
|       |   0x00401588      837dfc0b       cmp dword [local_4h], 0xb   ; [0xb:4]=-1 ; 11
|      ,==< 0x0040158c      7448           je 0x4015d6
|      ||   0x0040158e      837dfc02       cmp dword [local_4h], 2     ; [0x2:4]=-1 ; 2
|     ,===< 0x00401592      7562           jne 0x4015f6
|     |||   0x00401594      488d0d8e2a00.  lea rcx, str.CANCELING      ; 0x404029 ; "CANCELING"
|     |||   0x0040159b      e850150000     call sym.printf             ; int printf(const char *format)
|     |||   0x004015a0      ba2c010000     mov edx, 0x12c              ; rdx      
|     |||   0x004015a5      b9ee020000     mov ecx, 0x2ee              ; 750
|     |||   0x004015aa      488b054f6c00.  mov rax, qword sym.imp.KERNEL32.dll_Beep ; [0x408200:8]=0x778478f0
|     |||   0x004015b1      ffd0           call rax
|    ,====< 0x004015b3      eb41           jmp 0x4015f6
|    ||||   ; JMP XREF from 0x00401586 (sym.main)
|    |||`-> 0x004015b5      488d0d772a00.  lea rcx, str.Shall_we_try_again ; 0x404033 ; "Shall we try again?"
|    |||    0x004015bc      e82f150000     call sym.printf             ; int printf(const char *format)
|    |||    0x004015c1      ba64000000     mov edx, 0x64               ; 'd' ; 100
|    |||    0x004015c6      b9fa000000     mov ecx, 0xfa               ; 250
|    |||    0x004015cb      488b052e6c00.  mov rax, qword sym.imp.KERNEL32.dll_Beep ; [0x408200:8]=0x778478f0
|    |||    0x004015d2      ffd0           call rax
|    |||,=< 0x004015d4      eb20           jmp 0x4015f6
|    ||||   ; JMP XREF from 0x0040158c (sym.main)
|    ||`--> 0x004015d6      488d0d6a2a00.  lea rcx, str.The_show_must_go_on ; 0x404047 ; "The show must go on"
|    || |   0x004015dd      e80e150000     call sym.printf             ; int printf(const char *format)
|    || |   0x004015e2      baf4010000     mov edx, 0x1f4              ; 500
|    || |   0x004015e7      b9b6030000     mov ecx, 0x3b6              ; 950
|    || |   0x004015ec      488b050d6c00.  mov rax, qword sym.imp.KERNEL32.dll_Beep ; [0x408200:8]=0x778478f0
|    || |   0x004015f3      ffd0           call rax
|    || |   0x004015f5      90             nop
|    || |   ; JMP XREF from 0x004015d4 (sym.main)
|    || |   ; JMP XREF from 0x004015b3 (sym.main)
|    || |   ; JMP XREF from 0x00401592 (sym.main)
|    ``-`-> 0x004015f6      b800000000     mov eax, 0
|           0x004015fb      4883c430       add rsp, 0x30               ; '0'
|           0x004015ff      5d             pop rbp
\           0x00401600      c3             ret
[0x004015a5]>
```
Again, we can break the program in interesting slices to get the picture:
```
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401550      55             push rbp
|           0x00401551      4889e5         mov rbp, rsp
|           0x00401554      4883ec30       sub rsp, 0x30               ; '0'
|           0x00401558      e863010000     call sym.__main
|           0x0040155d      41b936000000   mov r9d, 0x36               ; '6' ; 54
|           0x00401563      4c8d05962a00.  lea r8, str.Artikblue_s_magic_msgbox ; section..rdata ; 0x404000 ; "Artikblue's magic msgbox"
|           0x0040156a      488d15a82a00.  lea rdx, str.Hello_dear_user ; 0x404019 ; "Hello dear user"
|           0x00401571      b900000000     mov ecx, 0
|           0x00401576      488b05236e00.  mov rax, qword sym.imp.USER32.dll_MessageBoxA ; [0x4083a0:8]=0x86d8 reloc.USER32.dll_MessageBoxA
|           0x0040157d      ffd0           call rax
|           0x0040157f      8945fc         mov dword [local_4h], eax
```
As we see, the program first keeps some space on the stack (ox30), then goes to main. Then the parameters are being passed to the MessageBox function and as you see the flags are being passed all together (combined) to the function so 6 is the combination of the values of those flags: 0x30 + 0x6

You can get the full list of flags for window creation here: https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox

Also note how the address relative to MessageBoxA is being loaded in rax then called there, why that? Probably because that address is being dynamically resolved somehow when the program loads or whatever, it does not matter for us for now.



Then the switch statement kicks in:

```
|           0x0040157f      8945fc         mov dword [local_4h], eax
|           0x00401582      837dfc0a       cmp dword [local_4h], 0xa   ; [0xa:4]=-1 ; 10
|       ,=< 0x00401586      742d           je 0x4015b5
|       |   0x00401588      837dfc0b       cmp dword [local_4h], 0xb   ; [0xb:4]=-1 ; 11
|      ,==< 0x0040158c      7448           je 0x4015d6
|      ||   0x0040158e      837dfc02       cmp dword [local_4h], 2     ; [0x2:4]=-1 ; 2
```

The MessageBox window offers the possibilit to do three actions, and as it is a sync process, the program won't continue until the user clicks. When returning eax will hold a value related to the user choice that will correspond to the clicked button 

Codes can be found here: https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox

So after the click, the program will check for the user action and run the corresponding piece of code:

Then again we see this difference, printf is called directly and then the Beep function (related to the kernel32 library), the parameters related to the beep frequencies are passed through those registers and then the func is called
```
|     ,===< 0x00401592      7562           jne 0x4015f6
|     |||   0x00401594      488d0d8e2a00.  lea rcx, str.CANCELING      ; 0x404029 ; "CANCELING"
|     |||   0x0040159b      e850150000     call sym.printf             ; int printf(const char *format)
|     |||   0x004015a0      ba2c010000     mov edx, 0x12c              ; 300
|     |||   0x004015a5      b9ee020000     mov ecx, 0x2ee              ; 750
|     |||   0x004015aa      488b054f6c00.  mov rax, qword sym.imp.KERNEL32.dll_Beep ; [0x408200:8]=0x83b0 reloc.KERNEL32.dll_Beep
|     |||   0x004015b1      ffd0           call rax
|    ,====< 0x004015b3      eb41           jmp 0x4015f6
```

Nothing much more to comment here, I just wanted to show how a C program can intereact with Windows operating system functionalities (somehow a little bit similar to Linux syscalls) easily.

Let's now get into more "systems programming" - like stuff, like the winapi way to deal with files.

#### Write a file to disk CreateFile and WriteFile

```C
#include <windows.h>
#include <stdio.h>

int main(void)

{
    DWORD at;

    HANDLE hFile;
    LPCWSTR fname = "C:\\samples\\newfile.txt";
    DWORD lpdwFlags[100];
    BOOL test;

    hFile = CreateFile(fname, GENERIC_WRITE,FILE_SHARE_WRITE,NULL,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL |FILE_ATTRIBUTE_ARCHIVE | SECURITY_IMPERSONATION,NULL);

    if(hFile == INVALID_HANDLE_VALUE)
        printf("Could not open %s file, error %d\n", fname, GetLastError());
    else{
        printf("File's HANDLE is OK!\n");
        printf("f handle = %d \n", hFile);
        char arr[20] = "SAMPLESAMPLESAMPLETEXT";
        printf("%s \n", arr);
        WriteFile(hFile, arr, 5,&at,NULL);
        printf("Bytes written: %d \n", at);
        CloseHandle(hFile);
    }

return 0;
}
```


Let's diisasm this:
```
[0x00401550]> pdf
/ (fcn) sym.main 343
|   sym.main (int arg_17ch, int arg_180h, int arg_188h);
|           ; var int local_40h @ rbp-0x40
|           ; var int local_38h @ rbp-0x38
|           ; var int local_30h_2 @ rbp-0x30
|           ; arg int arg_17ch @ rbp+0x17c
|           ; arg int arg_180h @ rbp+0x180
|           ; arg int arg_188h @ rbp+0x188
|           ; var int local_20h @ rsp+0x20
|           ; var int local_28h @ rsp+0x28
|           ; var int local_30h @ rsp+0x30
|           ; var int local_80h @ rsp+0x80
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401550      55             push rbp
|           0x00401551      4881ec100200.  sub rsp, 0x210
|           0x00401558      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x00401560      e8fb010000     call sym.__main
|           0x00401565      488d05942a00.  lea rax, str.C:__samples___ewfile.txt ; section..rdata ; 0x404000 ; "C:\samples\newfile.txt"
|           0x0040156c      488985880100.  mov qword [arg_188h], rax   ; [0x188:8]=-1 ; 392
|           0x00401573      488b85880100.  mov rax, qword [arg_188h]   ; [0x188:8]=-1 ; 392
|           0x0040157a      48c744243000.  mov qword [local_30h], 0
|           0x00401583      c7442428a000.  mov dword [local_28h], 0x200a0 ; [0x200a0:4]=-1
|           0x0040158b      c74424200200.  mov dword [local_20h], 2
|           0x00401593      41b900000000   mov r9d, 0
|           0x00401599      41b802000000   mov r8d, 2
|           0x0040159f      ba00000040     mov edx, 0x40000000
|           0x004015a4      4889c1         mov rcx, rax
|           0x004015a7      488b054e6c00.  mov rax, qword sym.imp.KERNEL32.dll_CreateFileA ; [0x4081fc:8]=0x83ba reloc.KERNEL32.dll_CreateFileA
|           0x004015ae      ffd0           call rax
|           0x004015b0      488985800100.  mov qword [arg_180h], rax   ; [0x180:8]=-1 ; 384
|           0x004015b7      4883bd800100.  cmp qword [arg_180h], 0xffffffffffffffff
|       ,=< 0x004015bf      7529           jne 0x4015ea
|       |   0x004015c1      488b05646c00.  mov rax, qword sym.imp.KERNEL32.dll_GetLastError ; [0x40822c:8]=0x8438 reloc.KERNEL32.dll_GetLastError ; "8\x84"
|       |   0x004015c8      ffd0           call rax
|       |   0x004015ca      89c2           mov edx, eax
|       |   0x004015cc      488b85880100.  mov rax, qword [arg_188h]   ; [0x188:8]=-1 ; 392
|       |   0x004015d3      4189d0         mov r8d, edx
|       |   0x004015d6      4889c2         mov rdx, rax
|       |   0x004015d9      488d0d382a00.  lea rcx, str.Could_not_open__s_file__error__d ; 0x404018 ; "Could not open %s file, error %d\n"
|       |   0x004015e0      e8b3150000     call sym.printf             ; int printf(const char *format)
|      ,==< 0x004015e5      e9af000000     jmp 0x401699
|      ||   ; JMP XREF from 0x004015bf (sym.main)
|      |`-> 0x004015ea      488d0d492a00.  lea rcx, str.File_s_HANDLE_is_OK ; 0x40403a ; "File's HANDLE is OK!"
|      |    0x004015f1      e89a150000     call sym.puts               ; int puts(const char *s)
|      |    0x004015f6      488b85800100.  mov rax, qword [arg_180h]   ; [0x180:8]=-1 ; 384
|      |    0x004015fd      4889c2         mov rdx, rax
|      |    0x00401600      488d0d482a00.  lea rcx, str.f_handle____d  ; 0x40404f ; "f handle = %d \n"
|      |    0x00401607      e88c150000     call sym.printf             ; int printf(const char *format)
|      |    0x0040160c      48b853414d50.  movabs rax, 0x4153454c504d4153
|      |    0x00401616      488945c0       mov qword [local_40h], rax
|      |    0x0040161a      48b84d504c45.  movabs rax, 0x504d4153454c504d
|      |    0x00401624      488945c8       mov qword [local_38h], rax
|      |    0x00401628      c745d04c4554.  mov dword [local_30h_2], 0x4554454c
|      |    0x0040162f      488d45c0       lea rax, [local_40h]
|      |    0x00401633      4889c2         mov rdx, rax
|      |    0x00401636      488d0d222a00.  lea rcx, str.s              ; 0x40405f ; "%s \n"
|      |    0x0040163d      e856150000     call sym.printf             ; int printf(const char *format)
|      |    0x00401642      488d957c0100.  lea rdx, [arg_17ch]         ; 0x17c ; 380
|      |    0x00401649      488d45c0       lea rax, [local_40h]
|      |    0x0040164d      488b8d800100.  mov rcx, qword [arg_180h]   ; [0x180:8]=-1 ; 384
|      |    0x00401654      48c744242000.  mov qword [local_20h], 0
|      |    0x0040165d      4989d1         mov r9, rdx
|      |    0x00401660      41b805000000   mov r8d, 5
|      |    0x00401666      4889c2         mov rdx, rax
|      |    0x00401669      488b054c6c00.  mov rax, qword sym.imp.KERNEL32.dll_WriteFile ; [0x4082bc:8]=0x85b0 reloc.KERNEL32.dll_WriteFile
|      |    0x00401670      ffd0           call rax
|      |    0x00401672      8b857c010000   mov eax, dword [arg_17ch]   ; [0x17c:4]=-1 ; 380
|      |    0x00401678      89c2           mov edx, eax
|      |    0x0040167a      488d0de32900.  lea rcx, str.Bytes_written:__d ; 0x404064 ; "Bytes written: %d \n"
|      |    0x00401681      e812150000     call sym.printf             ; int printf(const char *format)
|      |    0x00401686      488b85800100.  mov rax, qword [arg_180h]   ; [0x180:8]=-1 ; 384
|      |    0x0040168d      4889c1         mov rcx, rax
|      |    0x00401690      488b055d6b00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x4081f4:8]=0x83ac reloc.KERNEL32.dll_CloseHandle
|      |    0x00401697      ffd0           call rax
|      |    ; JMP XREF from 0x004015e5 (sym.main)
|      `--> 0x00401699      b800000000     mov eax, 0
|           0x0040169e      4881c4100200.  add rsp, 0x210
|           0x004016a5      5d             pop rbp
\           0x004016a6      c3             ret
[0x00401550]>
```
Things start to get interesting here, at first, the program calles CreateFile to actually create a file on disk. CreateFile can be used for creating a new file or for opening an existing one.

Whats interesting regarding to this function is that it will return a handle to the newle created/opened file. That handle will be used for read/write/seek operations on the file.
```
|           0x0040158b      c74424200200.  mov dword [local_20h], 2
|           0x00401593      41b900000000   mov r9d, 0
|           0x00401599      41b802000000   mov r8d, 2
|           0x0040159f      ba00000040     mov edx, 0x40000000
|           0x004015a4      4889c1         mov rcx, rax
|           0x004015a7      488b054e6c00.  mov rax, qword sym.imp.KERNEL32.dll_CreateFileA ; [0x4081fc:8]=0x83ba reloc.KERNEL32.dll_CreateFileA
|           0x004015ae      ffd0           call rax
|           0x004015b0 b    488985800100.  mov qword [arg_180h], rax   ; [0x180:8]=-1 ; 384
|           0x004015b7      4883bd800100.  cmp qword [arg_180h], 0xffffffffffffffff
|       ,=< 0x004015bf      7529           jne 0x4015ea
|       |   0x004015c1      488b05646c00.  mov rax, qword sym.imp.KERNEL32.dll_GetLastError ; [0x40822c:8]=0x8438 reloc.KERNEL32.dll_GetLastError ; "8\x84"
|       |   0x004015c8      ffd0           call rax
```

So here's the handle after the file gets opened
```
[0x004015b0]> dr rax
0x00000020
```

Then the program will check wether the file has been opened with an error or not, as CreateFile returns an int (file handle),  0xffffffffffffffff is associated with an error opening the file, so that cmp will check if the file opened correctly.
```
|           0x004015b0      488985800100.  mov qword [arg_180h], rax   ; [0x180:8]=-1 ; 384
            ;-- rip:
|           0x004015b7 b    4883bd800100.  cmp qword [arg_180h], 0xffffffffffffffff
|       ,=< 0x004015bf      7529           jne 0x4015ea
|       |   0x004015c1      488b05646c00.  mov rax, qword sym.imp.KERNEL32.dll_GetLastError ; [0x40822c:8]=0x77801300
|       |   0x004015c8      ffd0           call rax
```
At this point of the program, the file "newfile.txt" will exist on the filesystem with no content, and if we try to delete it, it won't be possible, because the file has been registered open by our program (as long as we have the file handle, the file is open and can only be accessed according to the flags you just saw on the code).

Then the program declares a simple array of chars (buffer) and calls WriteFile
```
|      |    0x00401669      488b054c6c00.  mov rax, qword sym.imp.KERNEL32.dll_WriteFile ; [0x4082bc:8]=0x77801a
       |    ;-- rip:
|      |    0x00401670 b    ffd0           call rax
|      |    0x00401672 b    8b857c010000   mov eax, dword [arg_17ch]   ; [0x17c:4]=-1 ; 380
|      |    0x00401678      89c2           mov edx, eax
|      |    0x0040167a      488d0de32900.  lea rcx, str.Bytes_written:__d ; 0x404064 ; "Bytes written: %d \n"
```
Right before the call, the program memory looks like this:
```
[0x00401670]> afvd
var arg_188h = 0x0022fe48  0x0000000000404000   .@@..... (IMAGE    winapi_CREATEFILE.exe | .data) section..rdata ascii R 0x6c706d61735c3a43 (C:\samples\newfi
var arg_180h = 0x0022fe40  0x0000000000000020    ....... rcx ascii
var local_40h = 0x0022fc80  0x4153454c504d4153   SAMPLESA @rdx ascii
var local_38h = 0x0022fc88  0x504d4153454c504d   MPLESAMP ascii
var local_30h_2 = 0x0022fc90  0x000000004554454c   LETE.... ascii
var arg_17ch = 0x0022fe3c  0x0000002000000000   .... ... @r9 ascii
[0x00401670]>

[0x00401670]> pxw @ 0x0022fc80
0x0022fc80  0x504d4153 0x4153454c 0x454c504d 0x504d4153  SAMPLESAMPLESAMP
0x0022fc90  0x4554454c 0x00000000 0x00611f50 0x00000000  LETE....P.a.....
0x0022fca0  0x77976850 0x00000000 0x00000001 0x00000000  Ph.w............
0x0022fcb0  0x00610000 0x00000000 0x14070013 0x00000000  ..a.............
```
As you can see, the program holds multiple references that correspond to parts of the array, that makes sense because the contents of the char array (string) have been initialised in memory for the program.

WriteFile is called with two interesting parameters here (file handle aside). Those are the byteswritten DWORD (double word ~= int) that will hold the number of bytes written to the file and 5, the actual number of bytes (characters) we want to write to file.

The byteswritten var will be updated after the writefile. After doing the write, arg_17ch in this case will be updated with 5 (if everything went ok)

````
[0x00401670]> dr
rax = 0x00000005
```
In this case the file won't be available (for reading) after the handle is freed byt CloseHandle. Let's see

```
|      |    0x0040168d      4889c1         mov rcx, rax
|      |    0x00401690      488b055d6b00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x4081f4:8]=0x778014b0
|      |    0x00401697      ffd0           call rax
|      |    ; JMP XREF from 0x004015e5 (sym.main)
|      `--> 0x00401699      b800000000     mov eax, 0
```
CloseHandle frees the file, and thus can be normally used in other programs.

All of the details regarding to WriteFile can be found on the msdn here: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile

Now that you get general idea on CreateFile and WriteFile I advice you to read this one: https://docs.microsoft.com/en-us/windows/win32/fileio/file-buffering if you want to know more about how WriteFile deals with this topic (temporal buffering and such)

#### Read and Write files ReadFile and WriteFile

As you can guess if we have a WriteFile call, we also have a ReadFile call as well. ReadFile works kind of the same, we need to pass similar variables to it such as the file handle, a buffer for the bytes to be read, the num of bytes to read and a pointer for "bytesread".

With Write/Read we can also use overlapping but I won't go deep on the topic (FOR NOW), read it here: https://docs.microsoft.com/en-us/windows/win32/devio/overlapped-operations 


So, the following program opens two files, one for Read and the other for Write, then it starts "transfering" bytes from one file to the other.
```C 
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define BUFFERSIZE 180

int main()
{
    printf("Reading %d bytes: \n", BUFFERSIZE);
    DWORD  dwBytesRead = 0;
    char   ReadBuffer[BUFFERSIZE] = {0};
    int err;
    int totalBytesRead = 0;
    int r = 0;
    int hFile = CreateFile("C:\\samples\\newfile.txt",               // file to open
                       GENERIC_READ,          // open for read
                       FILE_SHARE_READ,       // share for read
                       NULL,                  // default security
                       OPEN_EXISTING,         // existing file only
                       FILE_ATTRIBUTE_NORMAL, // normal file
                       NULL);

    int hFile2 = CreateFile("C:\\samples\\newfile2.txt",               // file to open
                       GENERIC_WRITE,          // open for write
                       FILE_SHARE_WRITE,       // share for reading
                       NULL,                  // default security
                       OPEN_EXISTING,         // existing file only
                       FILE_ATTRIBUTE_NORMAL, // normal file
                       NULL);

    if (hFile == INVALID_HANDLE_VALUE || hFile2 == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        printf("Error reading file, error code:  %d \n", err);

    }

    else{
        int fsize = GetFileSize(hFile, NULL);

        printf("File size in bytes: %d \n", fsize);

        printf("File content: \n");

        while(totalBytesRead < fsize){

            ReadFile(hFile, ReadBuffer, BUFFERSIZE-1, &dwBytesRead, NULL);
            printf("%s", ReadBuffer);
            totalBytesRead += dwBytesRead;

            WriteFile(hFile2, ReadBuffer, dwBytesRead,NULL,NULL);

        }

    }
    CloseHandle(hFile);
    CloseHandle(hFile2);

    return 0;
}
```

Let's check it, be ready cause the following disams is LARGE

```
[0x77953840]> s sym.main
[0x00401550]> pdf
/ (fcn) sym.main 580
|   sym.main (int arg_80h, int arg_84h, int arg_88h, int arg_8ch, int arg_90h, int arg_94h, int arg_98h, int arg_9ch);
|           ; var int local_40h @ rbp-0x40
|           ; arg int arg_80h @ rbp+0x80
|           ; arg int arg_84h @ rbp+0x84
|           ; arg int arg_88h @ rbp+0x88
|           ; arg int arg_8ch @ rbp+0x8c
|           ; arg int arg_90h @ rbp+0x90
|           ; arg int arg_94h @ rbp+0x94
|           ; arg int arg_98h @ rbp+0x98
|           ; arg int arg_9ch @ rbp+0x9c
|           ; var int local_20h @ rsp+0x20
|           ; var int local_28h @ rsp+0x28
|           ; var int local_30h @ rsp+0x30
|           ; var int local_80h @ rsp+0x80
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401550      55             push rbp
|           0x00401551      57             push rdi
|           0x00401552      4881ec280100.  sub rsp, 0x128
|           0x00401559      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x00401561      e8ea020000     call sym.__main
|           0x00401566      bab4000000     mov edx, 0xb4               ; 180
|           0x0040156b      488d0d8e2a00.  lea rcx, str.Reading__d_bytes: ; section..rdata ; 0x404000 ; "Reading %d bytes: \n"
|           0x00401572      e811170000     call sym.printf             ; int printf(const char *format)
|           0x00401577      c78580000000.  mov dword [arg_80h], 0      ; [0x80:4]=-1 ; 0
|           0x00401581      c78598000000.  mov dword [arg_98h], 0      ; [0x98:4]=-1 ; 0
|           0x0040158b      488d55c0       lea rdx, [local_40h]
|           0x0040158f      b800000000     mov eax, 0
|           0x00401594      b916000000     mov ecx, 0x16               ; 22
|           0x00401599      4889d7         mov rdi, rdx
|           0x0040159c      f348ab         rep stosq qword [rdi], rax
|           0x0040159f      4889fa         mov rdx, rdi
|           0x004015a2      8902           mov dword [rdx], eax
|           0x004015a4      4883c204       add rdx, 4
|           0x004015a8      c7859c000000.  mov dword [arg_9ch], 0      ; [0x9c:4]=-1 ; 0
|           0x004015b2      c78594000000.  mov dword [arg_94h], 0      ; [0x94:4]=-1 ; 0
|           0x004015bc      48c744243000.  mov qword [local_30h], 0
|           0x004015c5      c74424288000.  mov dword [local_28h], 0x80 ; [0x80:4]=-1 ; 128
|           0x004015cd      c74424200300.  mov dword [local_20h], 3
|           0x004015d5      41b900000000   mov r9d, 0
|           0x004015db      41b801000000   mov r8d, 1
|           0x004015e1      ba00000080     mov edx, 0x80000000
|           0x004015e6      488d0d272a00.  lea rcx, str.C:__samples___ewfile.txt ; 0x404014 ; "C:\samples\newfile.txt"
|           0x004015ed      488b05186c00.  mov rax, qword sym.imp.KERNEL32.dll_CreateFileA ; [0x40820c:8]=0x83da reloc.KERNEL32.dll_CreateFileA
|           0x004015f4      ffd0           call rax
|           0x004015f6      898590000000   mov dword [arg_90h], eax    ; [0x90:4]=-1 ; 144
|           0x004015fc      48c744243000.  mov qword [local_30h], 0
|           0x00401605      c74424288000.  mov dword [local_28h], 0x80 ; [0x80:4]=-1 ; 128
|           0x0040160d      c74424200300.  mov dword [local_20h], 3
|           0x00401615      41b900000000   mov r9d, 0
|           0x0040161b      41b802000000   mov r8d, 2
|           0x00401621      ba00000040     mov edx, 0x40000000
|           0x00401626      488d0dfe2900.  lea rcx, str.C:__samples___ewfile2.txt ; 0x40402b ; "C:\samples\newfile2.txt"
|           0x0040162d      488b05d86b00.  mov rax, qword sym.imp.KERNEL32.dll_CreateFileA ; [0x40820c:8]=0x83da reloc.KERNEL32.dll_CreateFileA
|           0x00401634      ffd0           call rax
|           0x00401636      89858c000000   mov dword [arg_8ch], eax    ; [0x8c:4]=-1 ; 140
|           0x0040163c      83bd90000000.  cmp dword [arg_90h], 0xffffffffffffffff
|       ,=< 0x00401643      7409           je 0x40164e
|       |   0x00401645      83bd8c000000.  cmp dword [arg_8ch], 0xffffffffffffffff
|      ,==< 0x0040164c      7528           jne 0x401676
|      ||   ; JMP XREF from 0x00401643 (sym.main)
|      |`-> 0x0040164e      488b05ef6b00.  mov rax, qword sym.imp.KERNEL32.dll_GetLastError ; [0x408244:8]=0x8466 reloc.KERNEL32.dll_GetLastError ; "f\x84"
|      |    0x00401655      ffd0           call rax
|      |    0x00401657      898584000000   mov dword [arg_84h], eax    ; [0x84:4]=-1 ; 132
|      |    0x0040165d      8b8584000000   mov eax, dword [arg_84h]    ; [0x84:4]=-1 ; 132
|      |    0x00401663      89c2           mov edx, eax
|      |    0x00401665      488d0ddc2900.  lea rcx, str.Error_reading_file__error_code:___d ; 0x404048 ; "Error reading file, error code:  %d \n"
|      |    0x0040166c      e817160000     call sym.printf             ; int printf(const char *format)
|      |,=< 0x00401671      e9e7000000     jmp 0x40175d
|      ||   ; JMP XREF from 0x0040164c (sym.main)
|      `--> 0x00401676      8b8590000000   mov eax, dword [arg_90h]    ; [0x90:4]=-1 ; 144
|       |   0x0040167c      4898           cdqe
|       |   0x0040167e      ba00000000     mov edx, 0
|       |   0x00401683      4889c1         mov rcx, rax
|       |   0x00401686      488b05af6b00.  mov rax, qword sym.imp.KERNEL32.dll_GetFileSize ; [0x40823c:8]=0x8458 reloc.KERNEL32.dll_GetFileSize ; "X\x84"
|       |   0x0040168d      ffd0           call rax
|       |   0x0040168f      898588000000   mov dword [arg_88h], eax    ; [0x88:4]=-1 ; 136
|       |   0x00401695      8b8588000000   mov eax, dword [arg_88h]    ; [0x88:4]=-1 ; 136
|       |   0x0040169b      89c2           mov edx, eax
|       |   0x0040169d      488d0dca2900.  lea rcx, str.File_size_in_bytes:__d ; 0x40406e ; "File size in bytes: %d \n"
|       |   0x004016a4      e8df150000     call sym.printf             ; int printf(const char *format)
|       |   0x004016a9      488d0dd72900.  lea rcx, str.File_content:  ; 0x404087 ; "File content: "
|       |   0x004016b0      e8cb150000     call sym.puts               ; int puts(const char *s)
|      ,==< 0x004016b5      e991000000     jmp 0x40174b
|      ||   ; JMP XREF from 0x00401757 (sym.main)
|     .---> 0x004016ba      8b8590000000   mov eax, dword [arg_90h]    ; [0x90:4]=-1 ; 144
|     :||   0x004016c0      4898           cdqe
|     :||   0x004016c2      4889c1         mov rcx, rax
|     :||   0x004016c5      488d95800000.  lea rdx, [arg_80h]          ; 0x80 ; 128
|     :||   0x004016cc      488d45c0       lea rax, [local_40h]
|     :||   0x004016d0      48c744242000.  mov qword [local_20h], 0
|     :||   0x004016d9      4989d1         mov r9, rdx
|     :||   0x004016dc      41b8b3000000   mov r8d, 0xb3               ; 179
|     :||   0x004016e2      4889c2         mov rdx, rax
|     :||   0x004016e5      488b05906b00.  mov rax, qword sym.imp.KERNEL32.dll_ReadFile ; [0x40827c:8]=0x8500 reloc.KERNEL32.dll_ReadFile
|     :||   0x004016ec      ffd0           call rax
|     :||   0x004016ee      488d45c0       lea rax, [local_40h]
|     :||   0x004016f2      4889c2         mov rdx, rax
|     :||   0x004016f5      488d0d9a2900.  lea rcx, [0x00404096]       ; "%s"
|     :||   0x004016fc      e887150000     call sym.printf             ; int printf(const char *format)
|     :||   0x00401701      8b959c000000   mov edx, dword [arg_9ch]    ; [0x9c:4]=-1 ; 156
|     :||   0x00401707      8b8580000000   mov eax, dword [arg_80h]    ; [0x80:4]=-1 ; 128
|     :||   0x0040170d      01d0           add eax, edx
|     :||   0x0040170f      89859c000000   mov dword [arg_9ch], eax    ; [0x9c:4]=-1 ; 156
|     :||   0x00401715      488d85800000.  lea rax, [arg_80h]          ; 0x80 ; 128
|     :||   0x0040171c      89c2           mov edx, eax
|     :||   0x0040171e      8b858c000000   mov eax, dword [arg_8ch]    ; [0x8c:4]=-1 ; 140
|     :||   0x00401724      4898           cdqe
|     :||   0x00401726      4889c1         mov rcx, rax
|     :||   0x00401729      488d45c0       lea rax, [local_40h]
|     :||   0x0040172d      48c744242000.  mov qword [local_20h], 0
|     :||   0x00401736      41b900000000   mov r9d, 0
|     :||   0x0040173c      4189d0         mov r8d, edx
|     :||   0x0040173f      4889c2         mov rdx, rax
|     :||   0x00401742      488b05936b00.  mov rax, qword sym.imp.KERNEL32.dll_WriteFile ; [0x4082dc:8]=0x85ea reloc.KERNEL32.dll_WriteFile
|     :||   0x00401749      ffd0           call rax
|     :||   ; JMP XREF from 0x004016b5 (sym.main)
|     :`--> 0x0040174b      8b859c000000   mov eax, dword [arg_9ch]    ; [0x9c:4]=-1 ; 156
|     : |   0x00401751      3b8588000000   cmp eax, dword [arg_88h]    ; [0x88:4]=-1 ; 136
|     `===< 0x00401757      0f8c5dffffff   jl 0x4016ba
|       |   ; JMP XREF from 0x00401671 (sym.main)
|       `-> 0x0040175d      8b8590000000   mov eax, dword [arg_90h]    ; [0x90:4]=-1 ; 144
|           0x00401763      4898           cdqe
|           0x00401765      4889c1         mov rcx, rax
|           0x00401768      488b05956a00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x408204:8]=0x83cc reloc.KERNEL32.dll_CloseHandle
|           0x0040176f      ffd0           call rax
|           0x00401771      8b858c000000   mov eax, dword [arg_8ch]    ; [0x8c:4]=-1 ; 140
|           0x00401777      4898           cdqe
|           0x00401779      4889c1         mov rcx, rax
|           0x0040177c      488b05816a00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x408204:8]=0x83cc reloc.KERNEL32.dll_CloseHandle
|           0x00401783      ffd0           call rax
|           0x00401785      b800000000     mov eax, 0
|           0x0040178a      4881c4280100.  add rsp, 0x128
|           0x00401791      5f             pop rdi
|           0x00401792      5d             pop rbp
\           0x00401793      c3             ret
[0x00401550]>
```

Eventhough the program looks confusing, the magic happens here:

```
|      ,==< 0x004016b5      e991000000     jmp 0x40174b
|      ||   ; JMP XREF from 0x00401757 (sym.main)
|     .---> 0x004016ba      8b8590000000   mov eax, dword [arg_90h]    ; [0x90:4]=-1 ; 144
|     :||   0x004016c0      4898           cdqe
|     :||   0x004016c2      4889c1         mov rcx, rax
|     :||   0x004016c5      488d95800000.  lea rdx, [arg_80h]          ; 0x80 ; 128
|     :||   0x004016cc      488d45c0       lea rax, [local_40h]
|     :||   0x004016d0      48c744242000.  mov qword [local_20h], 0
|     :||   0x004016d9      4989d1         mov r9, rdx
|     :||   0x004016dc      41b8b3000000   mov r8d, 0xb3               ; 179
|     :||   0x004016e2      4889c2         mov rdx, rax
|     :||   0x004016e5      488b05906b00.  mov rax, qword sym.imp.KERNEL32.dll_ReadFile ; [0x40827c:8]=0x8500 reloc.KERNEL32.dll_ReadFile
|     :||   0x004016ec      ffd0           call rax
|     :||   0x004016ee      488d45c0       lea rax, [local_40h]
|     :||   0x004016f2      4889c2         mov rdx, rax
|     :||   0x004016f5      488d0d9a2900.  lea rcx, [0x00404096]       ; "%s"
|     :||   0x004016fc      e887150000     call sym.printf             ; int printf(const char *format)
|     :||   0x00401701      8b959c000000   mov edx, dword [arg_9ch]    ; [0x9c:4]=-1 ; 156
|     :||   0x00401707      8b8580000000   mov eax, dword [arg_80h]    ; [0x80:4]=-1 ; 128
|     :||   0x0040170d      01d0           add eax, edx
|     :||   0x0040170f      89859c000000   mov dword [arg_9ch], eax    ; [0x9c:4]=-1 ; 156
|     :||   0x00401715      488d85800000.  lea rax, [arg_80h]          ; 0x80 ; 128
|     :||   0x0040171c      89c2           mov edx, eax
|     :||   0x0040171e      8b858c000000   mov eax, dword [arg_8ch]    ; [0x8c:4]=-1 ; 140
|     :||   0x00401724      4898           cdqe
|     :||   0x00401726      4889c1         mov rcx, rax
|     :||   0x00401729      488d45c0       lea rax, [local_40h]
|     :||   0x0040172d      48c744242000.  mov qword [local_20h], 0
|     :||   0x00401736      41b900000000   mov r9d, 0
|     :||   0x0040173c      4189d0         mov r8d, edx
|     :||   0x0040173f      4889c2         mov rdx, rax
|     :||   0x00401742      488b05936b00.  mov rax, qword sym.imp.KERNEL32.dll_WriteFile ; [0x4082dc:8]=0x85ea reloc.KERNEL32.dll_WriteFile
|     :||   0x00401749      ffd0           call rax
|     :||   ; JMP XREF from 0x004016b5 (sym.main)
|     :`--> 0x0040174b      8b859c000000   mov eax, dword [arg_9ch]    ; [0x9c:4]=-1 ; 156
|     : |   0x00401751      3b8588000000   cmp eax, dword [arg_88h]    ; [0x88:4]=-1 ; 136
|     `===< 0x00401757      0f8c5dffffff   jl 0x4016ba
|       |   ; JMP XREF from 0x00401671 (sym.main)
```
I strongly recommend you to always check for loops, they usually represent solid works of code that run interesting stuff.

They key of this block and the new thing here is the ReadFile call

````
|     :||   0x004016c2      4889c1         mov rcx, rax
|     :||   0x004016c5      488d95800000.  lea rdx, [arg_80h]          ; 0x80 ; 128
|     :||   0x004016cc      488d45c0       lea rax, [local_40h]
|     :||   0x004016d0      48c744242000.  mov qword [local_20h], 0
|     :||   0x004016d9      4989d1         mov r9, rdx
|     :||   0x004016dc      41b8b3000000   mov r8d, 0xb3               ; 179
|     :||   0x004016e2      4889c2         mov rdx, rax
|     :||   0x004016e5      488b05906b00.  mov rax, qword sym.imp.KERNEL32.dll_ReadFile ; [0x40827c:8]=0x8500 reloc.KERNEL32.dll_ReadFile
|     :||   0x004016ec b    ffd0           call rax
|     :||   0x004016ee      488d45c0       lea rax, [local_40h]
|     :||   0x004016f2 b    4889c2         mov rdx, rax
|     :||   0x004016f5      488d0d9a2900.  lea rcx, [0x00404096]       ; "%s"
|     :||   0x004016fc      e887150000     call sym.printf             ; int printf(const char *format)
```
For us the most important parameters are the pointer to the mem space that will hold the bytes read and then the num of bytes to read. On this case 0xb3 is the num of bytes to read and those will be loaded inside local_40h

As we are already open for debug, we can just figure that out by setting breakpoints before and after the call and examining the memory:

```
[0x004016ec]> afvd
var arg_80h = 0x0022fe20  0x0000000000000000   ........ @r9 r15
var arg_98h = 0x0022fe38  0x0000000000000000   ........ r15
var local_40h = 0x0022fd60  0x0000000000000000   ........ @rdx r15
var arg_9ch = 0x0022fe3c  0x00371f8000000000   ......7.
var arg_94h = 0x0022fe34  0x0000000000000000   ........ r15
var arg_90h = 0x0022fe30  0x0000000000000020    ....... rcx ascii
var arg_8ch = 0x0022fe2c  0x0000002000000024   $... ... ascii
var arg_84h = 0x0022fe24  0x0000000500000000   ........
var arg_88h = 0x0022fe28  0x0000002400000005   ....$...
[0x004016ec]> dc
hit breakpoint at: 4016f2
[0x004016ec]> afvd
var arg_80h = 0x0022fe20  0x0000000000000005   ........
var arg_98h = 0x0022fe38  0x0000000000000000   ........ rdx
var local_40h = 0x0022fd60  0x0000004c504d4153   SAMPL... @rax ascii
var arg_9ch = 0x0022fe3c  0x00371f8000000000   ......7.
var arg_94h = 0x0022fe34  0x0000000000000000   ........ rdx
var arg_90h = 0x0022fe30  0x0000000000000020    ....... ascii
var arg_8ch = 0x0022fe2c  0x0000002000000024   $... ... ascii
var arg_84h = 0x0022fe24  0x0000000500000000   ........
var arg_88h = 0x0022fe28  0x0000002400000005   ....$...
[0x004016ec]>
```
Voilà

Then the num of bytes read is added every time to a particular variable (that CMPed at the end of the loop) 
```
|     :||   0x004016f5      488d0d9a2900.  lea rcx, [0x00404096]
|     :||   0x004016fc      e887150000     call sym.printf
|     :||   0x00401701      8b959c000000   mov edx, dword [arg_9ch]
|     :||   0x00401707      8b8580000000   mov eax, dword [arg_80h]
|     :||   0x0040170d      01d0           add eax, edx
|     :||   0x0040170f      89859c000000   mov dword [arg_9ch], eax
|     :||   0x00401715      488d85800000.  lea rax, [arg_80h]
|     :||   0x0040171c      89c2           mov edx, eax
```
That is probably the counter

We can see that the program is using a 179 byte buffer to temp save those bytes read and then to WriteFile them into the other file. If we are going quick and blind we can inspect the status of the variable like this

````
0x0022fe00  0x4f444e41 0x4554474d 0x41525458 0x4d4f444e  ANDOMGTEXTRANDOM
0x0022fe10  0x00455447 0x00000000 0x00000000 0x00000000  GTE.............
0x0022fe20  0x000000b3 0x00000000 0x00000861 0x00000024  ........a...$...
0x0022fe30  0x00000020 0x00000000 0x00000000 0x00000166   ...........f...
0x0022fe40  0x002e1f80 0x00000000 0x002e1f80 0x00000000  ................
0x0022fe50  0x002e1f40 0x00000000 0x004013c7 0x00000000  @.........@.....
[0x004016ee]> dc
hit breakpoint at: 4016ee
[0x004016ee]> pxw @ 0x0022fd60
0x0022fd60  0x41525458 0x4d4f444e 0x58455447 0x4e415254  XTRANDOMGTEXTRAN
0x0022fd70  0x474d4f44 0x54584554 0x444e4152 0x54474d4f  DOMGTEXTRANDOMGT
```
As we can see the "text" continues after the previous loaded text. And that's all for this one, CloseHandle is called next and the program is done, let's proceed with another example


#### CopyFile

As you saw, we've been MANUALLY copying that file by loading the contents of one file and progressively dumping them to the other one. In a similar way with what we done in the past tutorial by using SendFile (it is not exactly the same though) we can just do one call to copy the file to the other destionation without doing manual stuff, the function will do all the heavy lifting work internally.

Check that:
```C
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
int main()
{
    printf("Copying file using 'CopyFile'");
    int b = CopyFile("C:\\samples\\newfile.txt","C:\\samples\\newfile2.txt",0);
    if (!b) {
        int err =  GetLastError();
        printf("Error: %d",err);
    } else {
        printf("File copied\n");
    }
    return 0;
}
```
As you see, no file handles here, just the paths and we are done.

```
[0x00401550]> pdf
/ (fcn) sym.main 117
|   sym.main ();
|           ; var int local_8h @ rbp-0x8
|           ; var int local_4h @ rbp-0x4
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401550      55             push rbp
|           0x00401551      4889e5         mov rbp, rsp
|           0x00401554      4883ec30       sub rsp, 0x30               ; '0'
|           0x00401558      e823010000     call sym.__main
|           0x0040155d      488d0d9c2a00.  lea rcx, str.Copying_file_using__CopyFile ; section..rdata ; 0x404000 ; "Copying file using 'CopyFile'"
|           0x00401564      e84f150000     call sym.printf             ; int printf(const char *format)
|           0x00401569      41b800000000   mov r8d, 0
|           0x0040156f      488d15a82a00.  lea rdx, str.C:__samples___ewfile2.txt ; 0x40401e ; "C:\samples\newfile2.txt"
|           0x00401576      488d0db92a00.  lea rcx, str.C:__samples___ewfile.txt ; 0x404036 ; "C:\samples\newfile.txt"
|           0x0040157d      488b05606c00.  mov rax, qword sym.imp.KERNEL32.dll_CopyFileA ; [0x4081e4:8]=0x838c reloc.KERNEL32.dll_CopyFileA
|           0x00401584      ffd0           call rax
|           0x00401586      8945fc         mov dword [local_4h], eax
|           0x00401589      837dfc00       cmp dword [local_4h], 0
|       ,=< 0x0040158d      751f           jne 0x4015ae
|       |   0x0040158f      488b057e6c00.  mov rax, qword sym.imp.KERNEL32.dll_GetLastError ; [0x408214:8]=0x8408 reloc.KERNEL32.dll_GetLastError
|       |   0x00401596      ffd0           call rax
|       |   0x00401598      8945f8         mov dword [local_8h], eax
|       |   0x0040159b      8b45f8         mov eax, dword [local_8h]
|       |   0x0040159e      89c2           mov edx, eax
|       |   0x004015a0      488d0da62a00.  lea rcx, str.Error:__d      ; 0x40404d ; "Error: %d"
|       |   0x004015a7      e80c150000     call sym.printf             ; int printf(const char *format)
|      ,==< 0x004015ac      eb0c           jmp 0x4015ba
|      ||   ; JMP XREF from 0x0040158d (sym.main)
|      |`-> 0x004015ae      488d0da22a00.  lea rcx, str.File_copied    ; 0x404057 ; "File copied"
|      |    0x004015b5      e8f6140000     call sym.puts               ; int puts(const char *s)
|      |    ; JMP XREF from 0x004015ac (sym.main)
|      `--> 0x004015ba      b800000000     mov eax, 0
|           0x004015bf      4883c430       add rsp, 0x30               ; '0'
|           0x004015c3      5d             pop rbp
\           0x004015c4      c3             ret
[0x00401550]>
```
Nothing worth mentioning here you just see that the CopyFileA is being called with those two filepaths. Let's move on
#### Moving inside files LZSEEK

Same as we did with the fseek syscall in Linux we can also move inside a file by seeking. Everytime we read N bytes from a file or write N bytes to it the (internal) pointer to that file content moves N bytes, we manually move the pointer using seek 

Let's see this:
```C
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
int main()
{
    printf("Hello world!\n");
    char message[10] = "secret msg";
    int hFile = CreateFile("C:\\samples\\cat.jpg",               // file to open
                       GENERIC_WRITE,          // open for write
                       FILE_SHARE_WRITE,       // share for reading
                       NULL,                  // default security
                       OPEN_EXISTING,         // existing file only
                       FILE_ATTRIBUTE_NORMAL, // normal file
                       NULL);


    LZSeek(hFile,0,2); //0 bytes from the end

    WriteFile(hFile, message, 10,NULL,NULL);
    CloseHandle(hFile);
    return 0;
}
```
This program is interesting as it presents a concept that may or may not be new to you but it is widely used in ctf games or even some malware.

The program opens a JPG file, then uses LZSEEK to move at the end of the file, then writes the message there. So the program is not a text file its an image, but as you may know JPG files start with 	FF D8 FF E0 and end with FF D9 bytes  
All of the content (bytes) that go after the end signature won't be interpreted by a jpg visualizer, so adding content in files that way can be used to deliver hidden messages (or malware commands) the set of techniques that allow us to do that is called steganography!



#### Listing dirs, FindFirstFile and FindNextFile
All kind of operations related to the file system can be done with the Windows Api, by the way I think that the windows api is probably the best way to deal with operations on the filesystem. At the end, you'll find a lot of calls to the windows api when reversing most kind of malware samples, as they parse the file system for file infection / information hidding / information extraction extraction etc 

So winapi offers functions related to searching files on the disk, those are FindFirstFile and FindNextFile 

The following program will look for each .txt file on the filesystem:
```C 
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
int main()
{
    printf("Hello world!\n");

    WIN32_FIND_DATA FindFileData;
    HANDLE hFind;


    char base_path[MAX_DIR_LEN] = "C:\\samples\\stor\\";
    hFind = FindFirstFile("C:\\samples\\stor\\*.txt",&FindFileData);

    do{
        memset(base_path,0,MAX_DIR_LEN);
        strcpy(base_path,"C:\\samples\\stor\\");

        strcat(base_path,FindFileData.cFileName);
        printf("Name= %s \n",base_path );

    }
    while(FindNextFile(hFind, &FindFileData) != 0);

    printf("exit");
    CloseHandle(hFind);
    return 0;
}

```
FindFirstFile will be called for searching each .txt file on the samples\stor folder, a handler that relates to the actual search will be returned by the system and that handler will then be used to continue the search. We'll assume that the system keeps track of all of the searches going on and everytime FindNextFile is called for one specific search the pointer moves on one file (on the new file handler returned).


And the disasm of the main function will look like this one:

```
[0x00401550]> pdf
/ (fcn) sym.main 312
|   sym.main (int arg_b0h, int arg_1f8h);
|           ; var int local_60h @ rbp-0x60
|           ; var int local_58h @ rbp-0x58
|           ; var int local_50h @ rbp-0x50
|           ; var int local_48h @ rbp-0x48
|           ; arg int arg_b0h @ rbp+0xb0
|           ; arg int arg_1f8h @ rbp+0x1f8
|           ; var int local_80h @ rsp+0x80
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401550      55             push rbp
|           0x00401551      57             push rdi
|           0x00401552      4881ec880200.  sub rsp, 0x288
|           0x00401559      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x00401561      e8da010000     call sym.__main
|           0x00401566      488d0d932a00.  lea rcx, str.Hello_world    ; section..rdata ; 0x404000 ; "Hello world!"
|           0x0040156d      e806160000     call sym.puts               ; int puts(const char *s)
|           0x00401572      48b8433a5c73.  movabs rax, 0x6c706d61735c3a43
|           0x0040157c      488945a0       mov qword [local_60h], rax
|           0x00401580      48b865735c73.  movabs rax, 0x5c726f74735c7365
|           0x0040158a      488945a8       mov qword [local_58h], rax
|           0x0040158e      48c745b00000.  mov qword [local_50h], 0
|           0x00401596      488d55b8       lea rdx, [local_48h]
|           0x0040159a      b800000000     mov eax, 0
|           0x0040159f      b91d000000     mov ecx, 0x1d               ; 29
|           0x004015a4      4889d7         mov rdi, rdx
|           0x004015a7      f348ab         rep stosq qword [rdi], rax
|           0x004015aa      4889fa         mov rdx, rdi
|           0x004015ad      8902           mov dword [rdx], eax
|           0x004015af      4883c204       add rdx, 4
|           0x004015b3      488d85b00000.  lea rax, [arg_b0h]          ; 0xb0 ; 176
|           0x004015ba      4889c2         mov rdx, rax
|           0x004015bd      488d0d492a00.  lea rcx, str.C:__samples__stor___.txt ; 0x40400d ; "C:\samples\stor\*.txt"
|           0x004015c4      488b05516c00.  mov rax, qword sym.imp.KERNEL32.dll_FindFirstFileA ; [0x40821c:8]=0x840a reloc.KERNEL32.dll_FindFirstFileA ; "\n\x8
|           0x004015cb      ffd0           call rax
|           0x004015cd      488985f80100.  mov qword [arg_1f8h], rax   ; [0x1f8:8]=-1 ; 504
|           ; JMP XREF from 0x00401654 (sym.main)
|       .-> 0x004015d4      488d45a0       lea rax, [local_60h]
|       :   0x004015d8      41b804010000   mov r8d, 0x104              ; 260
|       :   0x004015de      ba00000000     mov edx, 0
|       :   0x004015e3      4889c1         mov rcx, rax
|       :   0x004015e6      e89d150000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|       :   0x004015eb      488d45a0       lea rax, [local_60h]
|       :   0x004015ef      48bf433a5c73.  movabs rdi, 0x6c706d61735c3a43
|       :   0x004015f9      488938         mov qword [rax], rdi
|       :   0x004015fc      48bf65735c73.  movabs rdi, 0x5c726f74735c7365
|       :   0x00401606      48897808       mov qword [rax + 8], rdi
|       :   0x0040160a      c6401000       mov byte [rax + 0x10], 0
|       :   0x0040160e      488d85b00000.  lea rax, [arg_b0h]          ; 0xb0 ; 176
|       :   0x00401615      488d502c       lea rdx, [rax + 0x2c]       ; ',' ; 44
|       :   0x00401619      488d45a0       lea rax, [local_60h]
|       :   0x0040161d      4889c1         mov rcx, rax
|       :   0x00401620      e843150000     call sym.strcat             ; char*strcat(char *s1, const char *s2)
|       :   0x00401625      488d45a0       lea rax, [local_60h]
|       :   0x00401629      4889c2         mov rdx, rax
|       :   0x0040162c      488d0df02900.  lea rcx, str.Name___s       ; 0x404023 ; "Name= %s \n"
|       :   0x00401633      e848150000     call sym.printf             ; int printf(const char *format)
|       :   0x00401638      488d85b00000.  lea rax, [arg_b0h]          ; 0xb0 ; 176
|       :   0x0040163f      488b8df80100.  mov rcx, qword [arg_1f8h]   ; [0x1f8:8]=-1 ; 504
|       :   0x00401646      4889c2         mov rdx, rax
|       :   0x00401649      488b05d46b00.  mov rax, qword sym.imp.KERNEL32.dll_FindNextFileA ; [0x408224:8]=0x841c reloc.KERNEL32.dll_FindNextFileA
|       :   0x00401650      ffd0           call rax
|       :   0x00401652      85c0           test eax, eax
|       `=< 0x00401654      0f857affffff   jne 0x4015d4
|           0x0040165a      488d0dcd2900.  lea rcx, str.exit           ; 0x40402e ; "exit"
|           0x00401661      e81a150000     call sym.printf             ; int printf(const char *format)
|           0x00401666      488b85f80100.  mov rax, qword [arg_1f8h]   ; [0x1f8:8]=-1 ; 504
|           0x0040166d      4889c1         mov rcx, rax
|           0x00401670      488b058d6b00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x408204:8]=0x83cc reloc.KERNEL32.dll_CloseHandle
|           ; JMP XREF from 0x00401601 (sym.main)
|           0x00401677      ffd0           call rax
|           0x00401679      b800000000     mov eax, 0
|           0x0040167e      4881c4880200.  add rsp, 0x288
|           0x00401685      5f             pop rdi
|           0x00401686      5d             pop rbp
\           0x00401687      c3             ret
[0x00401550]>
```



```
|           0x004015bd      488d0d492a00.  lea rcx, str.C:__samples__stor___.txt ; 0x40400d ; "C:\samples\stor\*.txt"
|           0x004015c4      488b05516c00.  mov rax, qword sym.imp.KERNEL32.dll_FindFirstFileA ; [0x40821c:8]=0x7751c530 ; "0\xc5Qw"
|           0x004015cb      ffd0           call rax
            ;-- rip:
|           0x004015cd b    488985f80100.  mov qword [arg_1f8h], rax   ; [0x1f8:8]=-1 ; 504
|           ; JMP XREF from 0x00401654 (sym.main)

[0x004015cd]> dr rax
0x00255850
```

The struct for the file info is now loaded inside our arg_b0h variable

```
[0x004015cd]> afvd
var local_60h = 0x0022fbe0  0x6c706d61735c3a43   C:\sampl ascii
var local_58h = 0x0022fbe8  0x5c726f74735c7365   es\stor\ ascii
var local_50h = 0x0022fbf0  0x0000000000000000   ........ r15
var local_48h = 0x0022fbf8  0x0000000000000000   ........ r15
var arg_b0h = 0x0022fcf0  0xcadba01200000020    .......
var arg_1f8h = 0x0022fe38  0x000000000000002c   ,....... rsi ascii

[0x004015cd]> pxw @ 0x0022fcf0
0x0022fcf0  0x00000020 0xcadba012 0x01d632af 0xcadba012   ........2......
0x0022fd00  0x01d632af 0x0bff61f4 0x01d632b3 0x00000000  .2...a...2......
0x0022fd10  0x00000005 0x00000000 0x004a1f00 0x66647367  ..........J.gsdf
0x0022fd20  0x66647367 0x78742e67 0x50000074 0x00000000  gsdfg.txt..P....
0x0022fd30  0x004a0001 0x00000000 0x00000100 0x00000000  ..J.............
0x0022fd40  0x004a2cd0 0x00000000 0x00000010 0x00000000  .,J.............
0x0022fd50  0x004a2cd8 0x00000000 0x777741df 0x00000000  .,J......Aww....
0x0022fd60  0x004a0000 0x00000000 0x50000061 0x00000000  ..J.....a..P....
0x0022fd70  0x004a0000 0x00000000 0x00000008 0x00000000  ..J.............
```
The WIN32_FIND_DATA struct has the following aspect
```
typedef struct _WIN32_FIND_DATA { // wfd  
    DWORD dwFileAttributes; 
    FILETIME ftCreationTime; 
    FILETIME ftLastAccessTime; 
    FILETIME ftLastWriteTime; 
    DWORD    nFileSizeHigh; 
    DWORD    nFileSizeLow; 
    DWORD    dwReserved0; 
    DWORD    dwReserved1; 
    TCHAR    cFileName[ MAX_PATH ]; 
    TCHAR    cAlternateFileName[ 14 ]; 
} WIN32_FIND_DATA;
```

And we set a breakpoint after FindFirstFile is called run the program untill that point and then map the structure as we are already used to:

```
[0x004015cd]> "td struct w32find {int dwFileAttributes; long long ftCreationTime; long long ftLastAccessTime; long long ftLastWriteTime; int nFileSizeHigh; int
eserved0; int dwReserved1; char* cFileName; char* cAlternateFileName; };";
[0x004015cd]> tp w32find  @ 0x0022fcf0
   dwFileAttributes : 0x0022fcf0 = 32
     ftCreationTime : 0x0022fcf4 = (qword)0x01d632afcadba012
   ftLastAccessTime : 0x0022fcfc = (qword)0x01d632afcadba012
    ftLastWriteTime : 0x0022fd04 = (qword)0x01d632b30bff61f4
      nFileSizeHigh : 0x0022fd0c = 0
       nFileSizeLow : 0x0022fd10 = 5
        dwReserved0 : 0x0022fd14 = 0
        dwReserved1 : 0x0022fd18 = 4857600
          cFileName : 0x0022fd1c = gsdfgsdfg.txt
 cAlternateFileName : 0x0022fd2a =
[0x004015cd]>
```
You see, having a strong knowledge on data types and being able to do some research for internal structs related to the OS/Lang/Libs is fundamental, having this struct mapped will save a lot of time in the future, specially here where we have a loop that loads that struct with file data, file after file.

So we can easily grasp the filename and size, not bad.

Again, the magic about mapping the struct is that now we only need to set another breakpoint there, hit dc and then hit the up arrow two times and enter to get file information for each new file.
```
[0x004015cd]> db 0x00401652
[0x004015cd]> dc
hit breakpoint at: 401652
[0x00401652]> tp w32find  @ 0x0022fcf0
   dwFileAttributes : 0x0022fcf0 = 32
     ftCreationTime : 0x0022fcf4 = (qword)0x01d632afc88551c7
   ftLastAccessTime : 0x0022fcfc = (qword)0x01d632afc88551c7
    ftLastWriteTime : 0x0022fd04 = (qword)0x01d631fb3a23cec3
      nFileSizeHigh : 0x0022fd0c = 0
       nFileSizeLow : 0x0022fd10 = 5
        dwReserved0 : 0x0022fd14 = 7536743
        dwReserved1 : 0x0022fd18 = 6684772
          cFileName : 0x0022fd1c = newfile2 (2).txt
 cAlternateFileName : 0x0022fd2d =
[0x00401652]>
[0x00401652]>
```
And there we have the data, if you are wondering about what those hex numbers related to TIME data mean look:

0x01d632afc88551c7 = 132348969618854343dec and thats a TIMESTAMP = Monday, 25 May 2020 16:16:01, you can use plenty of online tools to parse this, like this one here: https://www.epochconverter.com/ldap so we defined the struct well it makes sense yayyyy!!

It is pretty common to find timestamps like that one on many programs, internally, those are the best way to represent datetime variables.

Let's now move on to a more complex example:

#### Xor Encrypting files 


