---
layout: post
title:  "Reverse engineering x64 binaries with Radare2 - 15 (Windows fundamentals: Intro to WinApi and file management)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_15.png
featured_image: assets/images/radare2/radare2_15.png
---

Today we are going to talk about the windows api, something that will allow us to do similar stuff as what we are doing with linux using syscalls.
#### WindowsAPI HelloWorld

The first program is always the hello wowrld and that is what we are going to do now.

So, Windows Api is what we use to interact with the windows operating system from the user space, according to wikipedia

"The Windows API, informally WinAPI, is Microsoft's core set of application programming interfaces (APIs) available in the Microsoft Windows operating systems. The name Windows API collectively refers to several different platform implementations that are often referred to by their own names (for example, Win32 API); see the versions section. Almost all Windows programs interact with the Windows API. On the Windows NT line of operating systems, a small number (such as programs started early in the Windows startup process) use the Native API"

You may be thinking about if winapi calls are syscalls or are the same as what we have saw on the past tutorial but know that you are not alone and some answers have been provided: https://www.quora.com/Why-does-Windows-have-the-Win32-API-for-invoking-system-calls-but-on-Linux-you-would-just-directly-invoke-the-system-call

The following answer states a good point that I want to remark, when we were going through Linux syscalls, we actually did no syscall at all, write()/open() etc are userland code they do the syscall internally but we can interpret them as syscalls for educational purposes.



Let's get to the code now:
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
The following code will use the Windows Api to pop a messagebox, a small dialog that will requiere the interaction of the user. Depending on the user action the program will do some stuff. That stuff will include emitting a simple "beep" using the systems audio (those params are related to the frequency). So, the key thing here is that MessageBox and Beep make use the operating systems features, that is important, those functions are not related to the specific language, not related to some calculations we want to perform, not related to data structures /algorithms those are actually ACTIONS we want the WINDOWS SYSTEM to do for us. So we use the api for dealing with operating system actions like generating a window or emitting a sound. A lot of windows malware makes use of the windows api because a malware deals with stuff like the filesystem/systems memory/registry/devices/network.

Having a nice understanding of the windows api makes it easy for malware analysis.

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

Let's continue with the very basics, as you see these msdn functions work relatively the same as the linux syscalls, we open a file for read/write creating it if it does  not exist with CreateFile and we get a handle to the file, a file handle or file handleR is somehow similar for us as a file descriptor, by using it we can reference the file, the system will hold information internally related to the file, for example, a pointer to the current position on the file, that will be updated afer a read/write/seek call on the file. 

So, following this logic, we can easily write some bytes to the file with WriteFile by using the file handle and some buffer with the bytes to write there. Note that when using Linux syscalls write/file descriptors is a MORE ADVANCED concept, as write is general it can write to the screen, to a file, to a socket, pipe whatever "because in linux everything is a file" here the thing is more like "in windows everything is an object" so eventhough the architecture is similar AT SOME POINT windows have a specific call for writing to a file, another call for sending info to the screen etc.

Whatever, here's the code:
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
        WriteFile(hFile, &arr, 5,&at,NULL);
        printf("Bytes written: %d \n", at);
        CloseHandle(hFile);
    }

return 0;
}
```
So basically the program opens a file for writting then checks if everythings ok with the open and calls WriteFile to write some bytes (arr).


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


After running this program, having the needed image on the right place on the filesystem, a "secret message" will be appended at the end, after the end signature. The image will open properly but the message will be there. We can actually open it with radare2 and inspect the message:

```
[0x00000000]> pxw
0x00000000  0xe0ffd8ff 0x464a1000 0x01004649 0x60000101  ......JFIF.....`
0x00000010  0x00006000 0x4300dbff 0x01010200 0x02010101  .`.....C........
0x00000020  0x02010101 0x02020202 0x02020304 0x04050202  ................
0x00000030  0x06040304 0x06060605 0x06060605 0x06080907  ................
0x00000040  0x06070907 0x080b0806 0x0a0a0a09 0x08060a0a  ................
0x00000050  0x0a0b0c0b 0x0a0a090c 0x00dbff0a 0x02020143  ............C...
0x00000060  0x02020202 0x05030305 0x0706070a 0x0a0a0a0a  ................
0x00000070  0x0a0a0a0a 0x0a0a0a0a 0x0a0a0a0a 0x0a0a0a0a  ................
0x00000080  0x0a0a0a0a 0x0a0a0a0a 0x0a0a0a0a 0x0a0a0a0a  ................
0x00000090  0x0a0a0a0a 0x0a0a0a0a 0x0a0a0a0a 0xc2ff0a0a  ................
0x000000a0  0x02081100 0x03200358 0x02002201 0x11030111  ....X. .."......
0x000000b0  0x00c4ff01 0x0200001c 0x01010302 0x00000000  ................
0x000000c0  0x00000000 0x05040000 0x02010603 0xff080007  ................
0x000000d0  0x011a00c4 0x01010300 0x00000101 0x00000000  ................
0x000000e0  0x00000000 0x00030201 0xff060504 0x030c00da  ................
0x000000f0  0x10020001 0x00001003 0x4ae1e801 0x497e596c  ...........JlY~Is?
```
As you see, the file presents the image format, we can seek to the end with sG and move -+ bytes with s-+ num

```
[0x00022f74]> px
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00022f74  ac71 8a48 5640 a2f8 693c e3d2 0a2d 0dc7  .q.HV@..i<...-..
0x00022f84  1c13 4c68 468f 0af5 841c 26a4 8445 8705  ..LhF.....&..E..
0x00022f94  6f10 0008 1a88 4aaf fb58 8c06 0a94 9f77  o.....J..X.....w
0x00022fa4  3930 dc8e 9b53 904e da85 843f 2fce 5b2e  90...S.N...?/.[.
0x00022fb4  c09a d499 d833 0fc0 8ee8 c874 1644 08f6  .....3.....t.D..
0x00022fc4  df3e c0c0 7f09 2555 4f0f a7d6 42a5 8e78  .>....%UO...B..x
0x00022fd4  383e 3de0 4605 9aae 7d4c 61f1 1a31 0430  8>=.F...}La..1.0
0x00022fe4  b0de bef3 91b6 1586 a035 38a9 2ae2 8956  .........58.*..V
0x00022ff4  d9eb 1e90 8890 8204 be79 fac7 4994 0d28  .........y..I..(
0x00023004  649e 262a 311c a58a 08a2 0ff7 789c d558  d.&*1.......x..X
0x00023014  55d0 2719 1a5d 0d32 b712 123f c39a 02ba  U.'..].2...?....
0x00023024  6c9b 2b7c 9382 9bba 054b 7491 efce 3183  l.+|.....Kt...1.
0x00023034  70bc d7e1 c51c f34b 4b07 5ffb 8cab 2c19  p......KK._...,.
0x00023044  d9dc 5ff1 926d 4135 7953 edc1 ac11 0661  .._..mA5yS.....a
0x00023054  1e7e b1f1 8090 db56 ff00 cc10 18c3 2822  .~.....V......("
0x00023064  be4f f39f ffd9 7365 6372 6574 206d 7367  .O....secret msg
[0x00022f74]> s+20
[0x00022f88]> px
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00022f88  468f 0af5 841c 26a4 8445 8705 6f10 0008  F.....&..E..o...
0x00022f98  1a88 4aaf fb58 8c06 0a94 9f77 3930 dc8e  ..J..X.....w90..
0x00022fa8  9b53 904e da85 843f 2fce 5b2e c09a d499  .S.N...?/.[.....
0x00022fb8  d833 0fc0 8ee8 c874 1644 08f6 df3e c0c0  .3.....t.D...>..
0x00022fc8  7f09 2555 4f0f a7d6 42a5 8e78 383e 3de0  ..%UO...B..x8>=.
0x00022fd8  4605 9aae 7d4c 61f1 1a31 0430 b0de bef3  F...}La..1.0....
0x00022fe8  91b6 1586 a035 38a9 2ae2 8956 d9eb 1e90  .....58.*..V....
0x00022ff8  8890 8204 be79 fac7 4994 0d28 649e 262a  .....y..I..(d.&*
0x00023008  311c a58a 08a2 0ff7 789c d558 55d0 2719  1.......x..XU.'.
0x00023018  1a5d 0d32 b712 123f c39a 02ba 6c9b 2b7c  .].2...?....l.+|
0x00023028  9382 9bba 054b 7491 efce 3183 70bc d7e1  .....Kt...1.p...
0x00023038  c51c f34b 4b07 5ffb 8cab 2c19 d9dc 5ff1  ...KK._...,..._.
0x00023048  926d 4135 7953 edc1 ac11 0661 1e7e b1f1  .mA5yS.....a.~..
0x00023058  8090 db56 ff00 cc10 18c3 2822 be4f f39f  ...V......(".O..
0x00023068  ffd9 7365 6372 6574 206d 7367 ffff ffff  ..secret msg....
0x00023078  ffff ffff ffff ffff ffff ffff ffff ffff  ................
```
And here we have our secret message!


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
Let's go step by step. As the code is a bit large and we already know about almost everything here, we'll focus on the new stuff

So we see that FindFirstFileA is called. You may be wondering why the "A", that A stands for ASCII, it means that the function will deal with ascii encoding, same call without the a can be found as well.

The call will return a search handle, an identifier for the ongoing search pointing to an internal structure that knows at what point on the search the progam is, then a "user" struct related to the last/actual file found will be updated.
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

The struct (WIN32_FIND_DATA) for the file info is now loaded inside our arg_b0h variable

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

Let's move on the last example:

```
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

#define MAX_DIR_LEN 260
#define BUF_SIZ 10
void cryp(char buf[]){

    char k[10] = "0123456789";

    for(int i = 0; i < sizeof(buf); i ++){
        buf[i] ^= k[i];
    }
}
void doFile(int hFile){
    char buf[BUF_SIZ];

    int totalBytesRead = 0;
    int dwBytesRead = 0;
    int fsize = GetFileSize(hFile, NULL);

    printf("File size in bytes: %d \n", fsize);

    printf("File content: \n");

    while(totalBytesRead < fsize){
        memset(buf,0,BUF_SIZ);
        ReadFile(hFile, buf, BUF_SIZ-1, &dwBytesRead, NULL);
        cryp(buf);
        LZSeek(hFile,-dwBytesRead,1);
        WriteFile(hFile, buf, dwBytesRead,NULL,NULL);
        printf("%s", buf);
        totalBytesRead += dwBytesRead;
    }
    printf("\n");
}

int main()
{
    printf("Hello world!\n");
    char base_path[MAX_DIR_LEN];

    WIN32_FIND_DATA FindFileData;
    HANDLE hFind;

    hFind = FindFirstFile("C:\\samples\\stor\\*.txt",&FindFileData);
    printf("Search handler = %d \n", hFind);

    do{
        memset(base_path,0,MAX_DIR_LEN);
        strcpy(base_path,"C:\\samples\\stor\\");

        strcat(base_path,FindFileData.cFileName);
        printf("Name= %s \n",base_path );

        int hFile = CreateFile(base_path,               // file to open
                       GENERIC_ALL,          // open for write
                       FILE_SHARE_WRITE | FILE_SHARE_READ,       // share for reading
                       NULL,                  // default security
                       OPEN_EXISTING,         // existing file only
                       FILE_ATTRIBUTE_NORMAL, // normal file
                       NULL);


        printf("File handle: %d \n", hFile);
        doFile(hFile);
    }
    while(FindNextFile(hFind, &FindFileData) != 0);
    return 0;
}
```
So this small poorly written program makes use of Find*File to go through a specific folder, open each file for read/write and XOR encrypt its bytes block by block it reads - xors - writes and moves on repeating the process. The key point is: as ReadFile and WriteFile both do move the file pointer N bytes forward, the progam makes use of seek for going back for writting the XORed content (then write will move the pointer back to the desired position).

Why do we go block by block? Easy, because we can XOR large files with this method, you don't want to map N GB in memory.

Also please note that this is purely a concept, this program may crash or not work very well on many systems (pointer stuff). Eventhough some malware uses encryption on the file system, for protecting itself or for attacking the system (cryptolockers) normally, they won't use lame code like the one I presented here! as the windows api already presents nice cryptography functionalities and there are also a bunch of free properly written and tested crypto libraries out there, we'll review those topics on the following tutorials. Said that, we can use this as a nice example.

Let's dig in there

```
[0x004016d8]> pdf
/ (fcn) sym.main 339
|   sym.main (int arg_100h, int arg_204h, int arg_208h);
|           ; var int local_40h @ rbp-0x40
|           ; arg int arg_100h @ rbp+0x100
|           ; arg int arg_204h @ rbp+0x204
|           ; arg int arg_208h @ rbp+0x208
|           ; var int local_20h @ rsp+0x20
|           ; var int local_28h @ rsp+0x28
|           ; var int local_30h @ rsp+0x30
|           ; var int local_80h @ rsp+0x80
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x004016d8      55             push rbp
|           0x004016d9      4881ec900200.  sub rsp, 0x290
|           0x004016e0      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x004016e8      e8f3010000     call sym.__main
|           0x004016ed      488d0d372900.  lea rcx, str.Hello_world    ; 0x40402b ; "Hello world!"
|           0x004016f4      e81f160000     call sym.puts               ; int puts(const char *s)
|           0x004016f9      488d45c0       lea rax, [local_40h]
|           0x004016fd      4889c2         mov rdx, rax
|           0x00401700      488d0d312900.  lea rcx, str.C:__samples__stor___.txt ; 0x404038 ; "C:\samples\stor\*.txt"
|           0x00401707      488b05366b00.  mov rax, qword sym.imp.KERNEL32.dll_FindFirstFileA ; [0x408244:8]=0x845a reloc.KERNEL32.dll_FindFirstFileA ; "Z\x84"
|           0x0040170e      ffd0           call rax
|           0x00401710      488985080200.  mov qword [arg_208h], rax   ; [0x208:8]=-1 ; 520
|           0x00401717      488b85080200.  mov rax, qword [arg_208h]   ; [0x208:8]=-1 ; 520
|           0x0040171e      4889c2         mov rdx, rax
|           0x00401721      488d0d262900.  lea rcx, str.Search_handler____d ; 0x40404e ; "Search handler = %d \n"
|           0x00401728      e8fb150000     call sym.printf             ; int printf(const char *format)
|           ; CODE XREF from 0x00401817 (sym.main)
|       .-> 0x0040172d      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x00401734      41b804010000   mov r8d, 0x104              ; 260
|       :   0x0040173a      ba00000000     mov edx, 0
|       :   0x0040173f      4889c1         mov rcx, rax
|       :   0x00401742      e8e9150000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|       :   0x00401747      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x0040174e      48ba433a5c73.  movabs rdx, 0x6c706d61735c3a43
|       :   0x00401758      488910         mov qword [rax], rdx
|       :   0x0040175b      48ba65735c73.  movabs rdx, 0x5c726f74735c7365
|       :   0x00401765      48895008       mov qword [rax + 8], rdx
|       :   0x00401769      c6401000       mov byte [rax + 0x10], 0
|       :   0x0040176d      488d45c0       lea rax, [local_40h]
|       :   0x00401771      488d502c       lea rdx, [rax + 0x2c]       ; ',' ; 44
|       :   0x00401775      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x0040177c      4889c1         mov rcx, rax
|       :   0x0040177f      e884150000     call sym.strcat             ; char *strcat(char *s1, const char *s2)
|       :   0x00401784      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x0040178b      4889c2         mov rdx, rax
|       :   0x0040178e      488d0dcf2800.  lea rcx, str.Name___s       ; 0x404064 ; "Name= %s \n"
|       :   0x00401795      e88e150000     call sym.printf             ; int printf(const char *format)
|       :   0x0040179a      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x004017a1      48c744243000.  mov qword [local_30h], 0
|       :   0x004017aa      c74424288000.  mov dword [local_28h], 0x80 ; [0x80:4]=-1 ; 128
|       :   0x004017b2      c74424200300.  mov dword [local_20h], 3
|       :   0x004017ba      41b900000000   mov r9d, 0
|       :   0x004017c0      41b803000000   mov r8d, 3
|       :   0x004017c6      ba00000010     mov edx, 0x10000000
|       :   0x004017cb      4889c1         mov rcx, rax
|       :   0x004017ce      488b05576a00.  mov rax, qword sym.imp.KERNEL32.dll_CreateFileA ; [0x40822c:8]=0x841c reloc.KERNEL32.dll_CreateFileA
|       :   0x004017d5      ffd0           call rax
|       :   0x004017d7      898504020000   mov dword [arg_204h], eax   ; [0x204:4]=-1 ; 516
|       :   0x004017dd      8b8504020000   mov eax, dword [arg_204h]   ; [0x204:4]=-1 ; 516
|       :   0x004017e3      89c2           mov edx, eax
|       :   0x004017e5      488d0d832800.  lea rcx, str.File_handle:__d ; 0x40406f ; "File handle: %d \n"
|       :   0x004017ec      e837150000     call sym.printf             ; int printf(const char *format)
|       :   0x004017f1      8b8504020000   mov eax, dword [arg_204h]   ; [0x204:4]=-1 ; 516
|       :   0x004017f7      89c1           mov ecx, eax
|       :   0x004017f9      e8bbfdffff     call sym.doFile
|       :   0x004017fe      488d45c0       lea rax, [local_40h]
|       :   0x00401802      488b8d080200.  mov rcx, qword [arg_208h]   ; [0x208:8]=-1 ; 520
|       :   0x00401809      4889c2         mov rdx, rax
|       :   0x0040180c      488b05396a00.  mov rax, qword sym.imp.KERNEL32.dll_FindNextFileA ; [0x40824c:8]=0x846c reloc.KERNEL32.dll_FindNextFileA ; "l\x84"
|       :   0x00401813      ffd0           call rax
|       :   0x00401815      85c0           test eax, eax
|       `=< 0x00401817      0f8510ffffff   jne 0x40172d
|           0x0040181d      b800000000     mov eax, 0
|           0x00401822      4881c4900200.  add rsp, 0x290
|           0x00401829      5d             pop rbp
\           0x0040182a      c3             ret
[0x004016d8]>   
```
Again, we face some initializations and a do-while style loop. When you see some block of code starting by a jmp forward then a cmp then a possible jump backwards it is clear that we are facing a while/for style loop, if we have a cmp-jmp backwards at the end of the block we have a do-while. It is important to be able to recognize those structures well as if/for/while are fundamental on programming and thus on reverse engineering programs :)

So, we have the findfirstfile call, then we enter inside the do-while.

Then the do-while starts with this:

```
|       :   0x0040173f      4889c1         mov rcx, rax
|       :   0x00401742      e8e9150000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|       :   0x00401747      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x0040174e      48ba433a5c73.  movabs rdx, 0x6c706d61735c3a43
|       :   0x00401758      488910         mov qword [rax], rdx
|       :   0x0040175b      48ba65735c73.  movabs rdx, 0x5c726f74735c7365
|       :   0x00401765      48895008       mov qword [rax + 8], rdx
|       :   0x00401769      c6401000       mov byte [rax + 0x10], 0
|       :   0x0040176d      488d45c0       lea rax, [local_40h]
|       :   0x00401771      488d502c       lea rdx, [rax + 0x2c]       ; ',' ; 44
|       :   0x00401775      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x0040177c      4889c1         mov rcx, rax
|       :   0x0040177f      e884150000     call sym.strcat             ; char *strcat(char *s1, const char *s2)
|       :   0x00401784      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x0040178b      4889c2         mov rdx, rax
|       :   0x0040178e      488d0dcf2800.  lea rcx, str.Name___s       ; 0x404064 ; "Name= %s \n"
|       :   0x00401795      e88e150000     call sym.printf             ; int printf(const char *format)   
```
Memset "deletes" the content of the char array used to hold the file_path, then manually loads the folders address back to the variable and concatenates the file name found with the base addr of the folder.

Note that at this point, var_40h will hold the struct related to the found file object, so + 0x2c is used for moving through the struct
```
|       :   0x00401769      c6401000       mov byte [rax + 0x10], 0
        :   ;-- rip:
|       :   0x0040176d b    488d45c0       lea rax, [local_40h]
|       :   0x00401771      488d502c       lea rdx, [rax + 0x2c]       ; ',' ; 44
|       :   0x00401775      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256
|       :   0x0040177c      4889c1         mov rcx, rax
|       :   0x0040177f      e884150000     call sym.strcat             ; char *strcat(char *s1, const char *s2)
|       :   0x00401784      488d85000100.  lea rax, [arg_100h]         ; 0x100 ; 256

[0x0040176d]> afvd
var local_40h = 0x0061fbd0  0x119893fa00000020    .......
arg arg_208h = 0x0061fe18  0x0000000000758160   `.u.....
arg arg_100h = 0x0061fd10  0x6c706d61735c3a43   C:\sampl @rax ascii
arg arg_204h = 0x0061fe14  0x0075816000000000   ....`.u.
var local_80h = 0x0061fc10  0x005c006500630069   i.c.e.\. @rbp ascii
var local_30h = 0x0061fbc0  0x0000000000000000   ........ r15
var local_28h = 0x0061fbb8  0x00007ffa97b377f3   .w......
var local_20h = 0x0061fbb0  0x8800000000593608   .6Y.....
[0x0040176d]> pxw @ 0x0061fbd0
0x0061fbd0  0x00000020 0x119893fa 0x01d63016 0x9b1838bf   ........0...8..
0x0061fbe0  0x01d63323 0x9ad559d3 0x01d63323 0x00000000  #3...Y..#3......
0x0061fbf0  0x000000c7 0x00000000 0x00000000 0x2e333333  ............333.
0x0061fc00  0x00747874 0x00000000 0x0044005c 0x00760065  txt.....\.D.e.v.
```
SO, the prgoram ends up opening the corresponding found file and then calls the doFile function sendinf the file handler like this:

```
|       :   0x004017f7      89c1           mov ecx, eax
        :   ;-- rip:
|       :   0x004017f9 b    e8bbfdffff     call sym.doFile
|       :   0x004017fe      488d45c0       lea rax, [local_40h]
|       :   0x00401802      488b8d080200.  mov rcx, qword [arg_208h]   ; [0x208:8]=-1 ; 520
|       :   0x00401809      4889c2         mov rdx, rax
|       :   0x0040180c      488b05396a00.  mov rax, qword sym.imp.KERNEL32.dll_FindNextFileA ; [0x40824c:8]=0x7ffa99f621a0
|       :   0x00401813      ffd0           call rax
|       :   0x00401815      85c0           test eax, eax
|       `=< 0x00401817      0f8510ffffff   jne 0x40172d
|           0x0040181d      b800000000     mov eax, 0
|           0x00401822      4881c4900200.  add rsp, 0x290
|           0x00401829      5d             pop rbp
\           0x0040182a      c3             ret
[0x004017f9]> dr ecx
0x000000ac
[0x004017f9]>    
```
Yes, that is the file handler, we can check that as we are debugging the program, the file handler (dec) should be on the screen at this point

```
[0x004017f9]> s sym.doFile
[0x004015b9]> pdf
/ (fcn) sym.doFile 287
|   sym.doFile (int arg_10h);
|           ; var int local_18h @ rbp-0x18
|           ; var int local_12h @ rbp-0x12
|           ; var int local_8h @ rbp-0x8
|           ; var int local_4h @ rbp-0x4
|           ; arg int arg_10h @ rbp+0x10
|           ; var int local_20h @ rsp+0x20
|           ; CALL XREF from 0x004017f9 (sym.main)
|           0x004015b9      55             push rbp
|           0x004015ba      4889e5         mov rbp, rsp
|           0x004015bd      4883ec50       sub rsp, 0x50               ; 'P'
|           0x004015c1      894d10         mov dword [arg_10h], ecx    ; r12 ; [0x10:4]=-1
|           0x004015c4      c745fc000000.  mov dword [local_4h], 0
|           0x004015cb      c745e8000000.  mov dword [local_18h], 0
|           0x004015d2      8b4510         mov eax, dword [arg_10h]    ; r12 ; [0x10:4]=-1
|           0x004015d5      4898           cdqe
|           0x004015d7      ba00000000     mov edx, 0
|           0x004015dc      4889c1         mov rcx, rax
|           0x004015df      488b05866c00.  mov rax, qword sym.imp.KERNEL32.dll_GetFileSize ; [0x40826c:8]=0x7ffa99f622b0
|           0x004015e6      ffd0           call rax
|           0x004015e8      8945f8         mov dword [local_8h], eax
|           0x004015eb      8b45f8         mov eax, dword [local_8h]
|           0x004015ee      89c2           mov edx, eax
|           0x004015f0      488d0d092a00.  lea rcx, str.File_size_in_bytes:__d ; section..rdata ; 0x404000 ; "File size in bytes: %d \n"
|           0x004015f7      e82c170000     call sym.printf             ; int printf(const char *format)
|           0x004015fc      488d0d162a00.  lea rcx, str.File_content:  ; 0x404019 ; "File content: "
|           0x00401603      e810170000     call sym.puts               ; int puts(const char *s)
|       ,=< 0x00401608      e9ae000000     jmp 0x4016bb
|       |   ; CODE XREF from 0x004016c1 (sym.doFile)
|      .--> 0x0040160d      488d45ee       lea rax, [local_12h]
|      :|   0x00401611      41b80a000000   mov r8d, 0xa
|      :|   0x00401617      ba00000000     mov edx, 0
|      :|   0x0040161c      4889c1         mov rcx, rax
|      :|   0x0040161f      e80c170000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|      :|   0x00401624      8b4510         mov eax, dword [arg_10h]    ; r12 ; [0x10:4]=-1
|      :|   0x00401627      4898           cdqe
|      :|   0x00401629      4889c1         mov rcx, rax
|      :|   0x0040162c      488d55e8       lea rdx, [local_18h]
|      :|   0x00401630      488d45ee       lea rax, [local_12h]
|      :|   0x00401634      48c744242000.  mov qword [local_20h], 0
|      :|   0x0040163d      4989d1         mov r9, rdx
|      :|   0x00401640      41b809000000   mov r8d, 9
|      :|   0x00401646      4889c2         mov rdx, rax
|      :|   0x00401649      488b05646c00.  mov rax, qword sym.imp.KERNEL32.dll_ReadFile ; [0x4082b4:8]=0x7ffa99f62410
|      :|   0x00401650      ffd0           call rax
|      :|   0x00401652      488d45ee       lea rax, [local_12h]
|      :|   0x00401656      4889c1         mov rcx, rax
|      :|   0x00401659      e8f2feffff     call sym.cryp
|      :|   0x0040165e      8b45e8         mov eax, dword [local_18h]
|      :|   0x00401661      f7d8           neg eax
|      :|   0x00401663      41b801000000   mov r8d, 1
|      :|   0x00401669      89c2           mov edx, eax
|      :|   0x0040166b      8b4d10         mov ecx, dword [arg_10h]    ; r12 ; [0x10:4]=-1
|      :|   0x0040166e      e835180000     call sym.LZSeek
|      :|   0x00401673      8b45e8         mov eax, dword [local_18h]
|      :|   0x00401676      89c2           mov edx, eax
|      :|   0x00401678      8b4510         mov eax, dword [arg_10h]    ; r12 ; [0x10:4]=-1
|      :|   0x0040167b      4898           cdqe
|      :|   0x0040167d      4889c1         mov rcx, rax
|      :|   0x00401680      488d45ee       lea rax, [local_12h]
|      :|   0x00401684      48c744242000.  mov qword [local_20h], 0
|      :|   0x0040168d      41b900000000   mov r9d, 0
|      :|   0x00401693      4189d0         mov r8d, edx
|      :|   0x00401696      4889c2         mov rdx, rax
|      :|   0x00401699      488b05746c00.  mov rax, qword sym.imp.KERNEL32.dll_WriteFile ; [0x408314:8]=0x7ffa99f62500
|      :|   0x004016a0      ffd0           call rax
|      :|   0x004016a2      488d45ee       lea rax, [local_12h]
|      :|   0x004016a6      4889c2         mov rdx, rax
|      :|   0x004016a9      488d0d782900.  lea rcx, [0x00404028]       ; "%s"
|      :|   0x004016b0      e873160000     call sym.printf             ; int printf(const char *format)
|      :|   0x004016b5      8b45e8         mov eax, dword [local_18h]
|      :|   0x004016b8      0145fc         add dword [local_4h], eax
|      :|   ; CODE XREF from 0x00401608 (sym.doFile)
|      :`-> 0x004016bb      8b45fc         mov eax, dword [local_4h]
|      :    0x004016be      3b45f8         cmp eax, dword [local_8h]
|      `==< 0x004016c1      0f8c46ffffff   jl 0x40160d
|           0x004016c7      b90a000000     mov ecx, 0xa
|           0x004016cc      e84f160000     call sym.putchar            ; int putchar(int c)
|           0x004016d1      90             nop
|           0x004016d2      4883c450       add rsp, 0x50               ; 'P'
|           0x004016d6      5d             pop rbp
\           0x004016d7      c3             ret
[0x004015b9]>                                                                                                                                      
```
So as you should already know, what kind of structure do we have here? YES a WHILE


```
|           0x004015df      488b05866c00.  mov rax, qword sym.imp.KERNEL32.dll_GetFileSize ; [0x40826c:8]=0x7ffa99f622b0
|           0x004015e6      ffd0           call rax
|           0x004015e8      8945f8         mov dword [local_8h], eax

|      :|   ; CODE XREF from 0x00401608 (sym.doFile)
|      :`-> 0x004016bb      8b45fc         mov eax, dword [local_4h]
|      :    0x004016be      3b45f8         cmp eax, dword [local_8h]
|      `==< 0x004016c1      0f8c46ffffff   jl 0x40160d
|           0x004016c7      b90a000000     mov ecx, 0xa
```
GetFileSize is called, size then stored inside local_8h and compared with local_4h we can easily guess that this loop actually goes through the file, reading N bytes chunk by chunk after it reaches the end by having read all of them.

Let's focus now on the loop itself:

```
|      :|   0x00401629      4889c1         mov rcx, rax
|      :|   0x0040162c      488d55e8       lea rdx, [local_18h]
|      :|   0x00401630      488d45ee       lea rax, [local_12h]
|      :|   0x00401634      48c744242000.  mov qword [local_20h], 0
|      :|   0x0040163d      4989d1         mov r9, rdx
|      :|   0x00401640      41b809000000   mov r8d, 9
|      :|   0x00401646      4889c2         mov rdx, rax
|      :|   0x00401649      488b05646c00.  mov rax, qword sym.imp.KERNEL32.dll_ReadFile ; [0x4082b4:8]=0x7ffa99f62410
```
The first thing that it does is reading from the file, how many bytes? 9 as we see, let's inspect those buffers after the read.

```
[0x00401652]> afvd
arg arg_10h = 0x0061fb90  0x00000000000000ac   ........
var local_4h = 0x0061fb7c  0x0061fc1000000000   ......a.
var local_18h = 0x0061fb68  0x6f4e000000000009   ......No
var local_8h = 0x0061fb78  0x00000000000000c7   ........
var local_12h = 0x0061fb6e  0x6961676120726f4e   Nor agai ascii
var local_20h = 0x0061fb50  0x0000000000000000   ........ rdx
[0x00401652]> pxw @ 0x0061fb6e
0x0061fb6e  0x20726f4e 0x69616761 0x00c7006e 0x00000000  Nor again.......
0x0061fb7e  0xfc100000 0x00000061 0x17fe0000 0x00000040  ....a.......@...
```
Thats it, 9 bytes being read, content dumpted to 0x0061fb6e, then it goes to the cryp function.

```
[0x00401550]> pdf
/ (fcn) sym.cryp 105
|   sym.cryp (int arg_10h);
|           ; var int local_eh @ rbp-0xe
|           ; var int local_6h @ rbp-0x6
|           ; var int local_4h @ rbp-0x4
|           ; arg int arg_10h @ rbp+0x10
|           ; CALL XREF from 0x00401659 (sym.doFile)
|           0x00401550      55             push rbp
|           0x00401551      4889e5         mov rbp, rsp
|           0x00401554      4883ec10       sub rsp, 0x10
|           0x00401558      48894d10       mov qword [arg_10h], rcx    ; r12 ; [0x10:8]=-1
|           0x0040155c      48b830313233.  movabs rax, 0x3736353433323130
|           0x00401566      488945f2       mov qword [local_eh], rax
|           0x0040156a      66c745fa3839   mov word [local_6h], 0x3938
|           0x00401570      c745fc000000.  mov dword [local_4h], 0
|       ,=< 0x00401577      eb31           jmp 0x4015aa
|       |   ; CODE XREF from 0x004015b0 (sym.cryp)
|      .--> 0x00401579      8b45fc         mov eax, dword [local_4h]
|      :|   0x0040157c      4898           cdqe
|      :|   0x0040157e      488b5510       mov rdx, qword [arg_10h]    ; r12 ; [0x10:8]=-1
|      :|   0x00401582      4801d0         add rax, rdx                ; '('
|      :|   0x00401585      440fb600       movzx r8d, byte [rax]
|      :|   0x00401589      8b45fc         mov eax, dword [local_4h]
|      :|   0x0040158c      4898           cdqe
|      :|   0x0040158e      0fb64c05f2     movzx ecx, byte [rbp + rax - 0xe]
|      :|   0x00401593      8b45fc         mov eax, dword [local_4h]
|      :|   0x00401596      4898           cdqe
|      :|   0x00401598      488b5510       mov rdx, qword [arg_10h]    ; r12 ; [0x10:8]=-1
|      :|   0x0040159c      4801d0         add rax, rdx                ; '('
|      :|   0x0040159f      4489c2         mov edx, r8d
|      :|   0x004015a2      31ca           xor edx, ecx
|      :|   0x004015a4      8810           mov byte [rax], dl
|      :|   0x004015a6      8345fc01       add dword [local_4h], 1
|      :|   ; CODE XREF from 0x00401577 (sym.cryp)
|      :`-> 0x004015aa      8b45fc         mov eax, dword [local_4h]
|      :    0x004015ad      83f807         cmp eax, 7                  ; 7
|      `==< 0x004015b0      76c7           jbe 0x401579
|           0x004015b2      90             nop
|           0x004015b3      4883c410       add rsp, 0x10
|           0x004015b7      5d             pop rbp
\           0x004015b8      c3             ret
[0x00401550]>                                                                                                                                         
```
Again, another for/while style loop. We can use the common sense here, function is labeled cryp, byte array (buffer) is sent, the XOR instruction is present there. Nothing much more to see...We can  guess that the buffer will be xored with something, and what about that something?

Well, we see a movabs -> 

```
|           0x00401558      48894d10       mov qword [arg_10h], rcx    ; r12 ; [0x10:8]=-1
|           0x0040155c      48b830313233.  movabs rax, 0x3736353433323130
|           0x00401566      488945f2       mov qword [local_eh], rax
|           0x0040156a b    66c745fa3839   mov word [local_6h], 0x3938
|           0x00401570      c745fc000000.  mov dword [local_4h], 0
|       ,=< 0x00401577      eb31           jmp 0x4015aa
|       |   ; CODE XREF from 0x004015b0 (sym.cryp)

[0x00401550]> dc
hit breakpoint at: 40156a
[0x00401550]> afvd
arg arg_10h = 0x0061fb30  0x000000000061fb6e   n.a..... (PRIVATE  ) rcx R W 0x6961676120726f4e (Nor again) -->  ascii
var local_eh = 0x0061fb12  0x3736353433323130   01234567 rax ascii sequence
var local_6h = 0x0061fb1a  0xfb8000000000001a   ........
var local_4h = 0x0061fb1c  0x0061fb8000000000   ......a.
[0x00401550]> pxw @ 0x0061fb12
0x0061fb12  0x33323130 0x37363534 0x0000001a 0xfb800000  01234567........
0x0061fb22  0x00000061 0x165e0000 0x00000040 0xfb6e0000  a.....^.@.....n.
```
We can assume a 0-7 ascii char array that will be used for a byte-by-byte xor here.
```
[0x0040165e]> pxw @ 0x0061fb6e
0x0061fb6e  0x13405e7e 0x5e575255 0x00c7006e 0x00000000  ~^@.URW^n.......
0x0061fb7e  0xfc100000 0x00000061 0x17fe0000 0x00000040  ....a.......@...
```
After the call that was the result.



They key thing is that LZSEEK is being used to move backwards for writting that content.

I will stop here for this tutorial. I suggest you to review those examples by building them and maybe automating some stuff with r2pipe.

On the next tutorial we'll talk about sockets!




Why is important to learn about the windows api? https://www.quora.com/Is-Win32-API-still-used