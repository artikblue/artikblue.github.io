---
layout: post
title:  "Reverse engineering x64 binaries with Radare2 - 16 (unix sockets fundamentals)"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_16.png
featured_image: assets/images/radare2/radare2_16.png
---

Today we'll talk about sockets, fundamental stuff on computer progams and used by many malware and exploits. We'll start from the very basics and move to some actual examples later on.

### About sockets

Sockets allow us to communicate between two different processes, the thing here is that those processess can be located in different systems, so they can be on the same machine or in different machines.

In Unix systems, as we presented, every input/output operation is done over file descriptors remember the "everything is a file" thing we talked about, so we can use read() and write() 

Sockets are used to perform network communications, common applications such as ftp, mail or web clients are built on top of them and many high level functions present in many libraries make an internal use of sockets.

Here I'm assuming that you already know about some networking fundamentals eg: what is an ip address vs what is a mac, ip classes and basic routing etc. You should also know about the fundamentals of domain name resolutions and the role of /etc/resolv.conf and /etc/hosts.


### Basic usage

In general terms network progams work in a client-server architecture where one program waits for a client connection, then the client connects they exchange data and that's it, the server can then wait for more connections and the client can re connect or connect to other servers. In P2P (peertopeer) architectures both programs act as client and server.

#### Client processes

A client process would create a socket then connect it to a remote server on a specific port and write/read content from/to a particular buffer, it then may clear the buffer and read again or close the connection freeing the socket and proceed with the program.

#### Server processes


A server would typically create a socket and bind it to an ip address and port then listen for connections. Those connections will be accepted and then the read/write will happen, at the end the process may repeat or the socket may be closed.

Servers can be "iterative" or "concurrent". An iterative server will accept connections one after another, a connection will be accepted and treated then the next one on queue will come and so on. Concurrent servers will treat many connections at the same time, by creating a new process for each connection.

The most basic client-server interaction through sockets will look like this, those calls actually correspond to the unix syscalls we'll be using after:

![diagram from tutorialspoint](https://www.tutorialspoint.com/unix_sockets/images/socket_client_server.gif)

### Unix sockets in C

#### Basic data structures

Various structures are used in Unix Socket Programming to hold information about the address and port, among other useful information. Most socket functions require a pointer to a socket address structure as an argument. 

So here we have the first structure

```c
struct sockaddr {
   unsigned short   sa_family;
   char             sa_data[14];
};
```

This one holds the basic socket info, sa_family it references the kind of socket we are working with, most of the programs use AF_INET. Then sa_data relates to the specific data related to the family socket, for example when using AF_INET sa_data will hold stuff like the remote ip and port

Then we have this second (complementary) structure over here:
```c
struct sockaddr_in {
   short int            sin_family;
   unsigned short int   sin_port;
   struct in_addr       sin_addr;
   unsigned char        sin_zero[8];
};
```
Very similar to the other, you can guess about those fields and just note that sin_zero is not used.

And finally we have this one:

```c
struct in_addr {
   unsigned long s_addr;
};
```
Used as sin_addr for the previous structure. Just note that s_addr represents ip, port in network byte order.

Other structures such as hostent and servent exist as well but we won't use them here.


#### About the network byte order

Not all computers store the bytes that comprise a multibyte value in the same order. Little Endian and Big Endian are the schemes you'll find out there.

In Little Endian, low-order byte is stored on the starting address (A) and high-order byte is stored on the next address (A + 1). And in Big Endian high-order byte is stored on the starting address (A) and low-order byte is stored on the next address (A + 1). Little Endian is very common.

To allow programs that may be running in different machines (that may employ their byte order) internet protocols (that are above individual physical machines) network byte order is implemented. So data in sin_port, sin_addr and sockaddr_in structs needs to be encoded in network byte order.

So the following functions are used to convert hosts from big/little endian to byte order and back, you'll see them in the code:

```
htons() host to network short
htonl() host to network long
ntohl() network to host long
ntohs() network to host short
```

```c
#include <stdio.h>

int main(int argc, char **argv) {

   union {
      short s;
      char c[sizeof(short)];
   }un;
	
   un.s = 0x0102;
   
   if (sizeof(short) == 2) {
      if (un.c[0] == 1 && un.c[1] == 2)
         printf("big-endian\n");
      
      else if (un.c[0] == 2 && un.c[1] == 1)
         printf("little-endian\n");
      
      else
         printf("unknown\n");
   }
   else {
      printf("sizeof(short) = %d\n", sizeof(short));
   }
	
   exit(0);
}
```

So, you get it right? As we previously saw, in a union like that that short s and the c array (the size of a short) will share space, then will be filled with 0x0102, so depending on where the last value, the 0x2 is stored we'll know if we are on a big endian or little endian system. 

Just out of curiosity, let us open it inside our favorite reversing framework

```
[0x564d509f9145]> pdf
            ; DATA XREF from entry0 @ 0x564d509f907d
┌ 118: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_14h @ rbp-0x14
│           ; var int64_t var_ah @ rbp-0xa
│           ; var int64_t var_9h @ rbp-0x9
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x564d509f9145      55             push rbp
│           0x564d509f9146      4889e5         mov rbp, rsp
│           0x564d509f9149      4883ec20       sub rsp, 0x20
│           0x564d509f914d      897dec         mov dword [var_14h], edi ; argc
│           0x564d509f9150      488975e0       mov qword [var_20h], rsi ; argv
│           0x564d509f9154      64488b042528.  mov rax, qword fs:[0x28]
│           0x564d509f915d      488945f8       mov qword [var_8h], rax
│           0x564d509f9161      31c0           xor eax, eax
│           0x564d509f9163      66c745f60201   mov word [var_ah], 0x102 ; 258
│           0x564d509f9169      0fb645f6       movzx eax, byte [var_ah]
│           0x564d509f916d      3c01           cmp al, 1               ; 1
│       ┌─< 0x564d509f916f      7516           jne 0x564d509f9187
│       │   0x564d509f9171      0fb645f7       movzx eax, byte [var_9h]
│       │   0x564d509f9175      3c02           cmp al, 2               ; 2
│      ┌──< 0x564d509f9177      750e           jne 0x564d509f9187
│      ││   0x564d509f9179      488d3d840e00.  lea rdi, str.big_endian ; 0x564d509fa004 ; "big-endian"
│      ││   0x564d509f9180      e8abfeffff     call sym.imp.puts       ; int puts(const char *s)
│     ┌───< 0x564d509f9185      eb2a           jmp 0x564d509f91b1
│     │└└─> 0x564d509f9187      0fb645f6       movzx eax, byte [var_ah]
│     │     0x564d509f918b      3c02           cmp al, 2               ; 2
│     │ ┌─< 0x564d509f918d      7516           jne 0x564d509f91a5
│     │ │   0x564d509f918f      0fb645f7       movzx eax, byte [var_9h]
│     │ │   0x564d509f9193      3c01           cmp al, 1               ; 1
│     │┌──< 0x564d509f9195      750e           jne 0x564d509f91a5
│     │││   0x564d509f9197      488d3d710e00.  lea rdi, str.little_endian ; 0x564d509fa00f ; "little-endian"
│     │││   0x564d509f919e      e88dfeffff     call sym.imp.puts       ; int puts(const char *s)
│    ┌────< 0x564d509f91a3      eb0c           jmp 0x564d509f91b1
│    ││└└─> 0x564d509f91a5      488d3d710e00.  lea rdi, str.unknown    ; 0x564d509fa01d ; "unknown"
│    ││     0x564d509f91ac      e87ffeffff     call sym.imp.puts       ; int puts(const char *s)
│    ││     ; CODE XREFS from main @ 0x564d509f9185, 0x564d509f91a3
│    └└───> 0x564d509f91b1      bf00000000     mov edi, 0
└           0x564d509f91b6      e885feffff     call sym.imp.exit       ; void exit(int status)
[0x564d509f9145]> 
```
So the value is first loaded, and then as we know that our number "starts" with 1 and ends with 2 we try to discover how it has been loaded in memory
```
│           0x55d1f3ec0163      66c745f60201   mov word [var_ah], 0x102 ; 258
│           0x55d1f3ec0169 b    0fb645f6       movzx eax, byte [var_ah]
│           0x55d1f3ec016d      3c01           cmp al, 1               ; 1
│       ┌─< 0x55d1f3ec016f      7516           jne 0x55d1f3ec0187
│       │   0x55d1f3ec0171      0fb645f7       movzx eax, byte [var_9h]
│       │   0x55d1f3ec0175      3c02           cmp al, 2               ; 2
│      ┌──< 0x55d1f3ec0177 b    750e           jne 0x55d1f3ec0187
│      ││   0x55d1f3ec0179      488d3d840e00.  lea rdi, str.big_endian ; 0x55d1f3ec1004 ; "big-endian"
│      ││   0x55d1f3ec0180      e8abfeffff     call sym.imp.puts       ; int puts(const char *s)
```
So we load the value and we see it in memory here, little endian
```
[0x55d1f3ec0169]> pxw @ 0x7ffeee763916
0x7ffeee763916  0x51000102 0x6efd5e62 0x01c009a0 0x55d1f3ec  ...Qb^.n.......U
```
And then we load it inside al and here we have it:
```
[0x55d1f3ec0169]> ds
[0x55d1f3ec016d]> dr al
0x00000002
```
Most of the machines we can find out there work in little endian.

So in many programs we would prefeer to work with IP addesses as ASCII strings or something like that, we have some interesting calls than can help us converting.

For example inet_aton(const char *strptr, struct in_addr *addrptr) converts the specified string in the Internet standard dot notation to a network address, and stores the address in the structure provided. The converted address will be in Network Byte Order (bytes ordered from left to right). It returns 1 if the string was valid and 0 on error.

Let's see how this works on the inside:

```c
#include <stdio.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {

int retval;
   struct in_addr addrptr;
   
   memset(&addrptr, '\0', sizeof(addrptr));
   retval = inet_aton("68.178.157.132", &addrptr);
   exit(0);
}
```

```
[0x55fdbfcb3155]> pdf
            ; DATA XREF from entry0 @ 0x55fdbfcb308d
┌ 84: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_14h @ rbp-0x14
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x55fdbfcb3155      55             push rbp
│           0x55fdbfcb3156      4889e5         mov rbp, rsp
│           0x55fdbfcb3159      4883ec20       sub rsp, 0x20
│           0x55fdbfcb315d      897dec         mov dword [var_14h], edi ; argc
│           0x55fdbfcb3160      488975e0       mov qword [var_20h], rsi ; argv
│           0x55fdbfcb3164      64488b042528.  mov rax, qword fs:[0x28]
│           0x55fdbfcb316d      488945f8       mov qword [var_8h], rax
│           0x55fdbfcb3171      31c0           xor eax, eax
│           0x55fdbfcb3173      488d45f0       lea rax, [var_10h]
│           0x55fdbfcb3177      ba04000000     mov edx, 4
│           0x55fdbfcb317c      be00000000     mov esi, 0
│           0x55fdbfcb3181      4889c7         mov rdi, rax
│           0x55fdbfcb3184      e8a7feffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
│           0x55fdbfcb3189      488d45f0       lea rax, [var_10h]
│           0x55fdbfcb318d      4889c6         mov rsi, rax
│           0x55fdbfcb3190      488d3d6d0e00.  lea rdi, str.68.178.157.132 ; 0x55fdbfcb4004 ; "68.178.157.132"
│           0x55fdbfcb3197      e8a4feffff     call sym.imp.inet_aton  ; int inet_aton(const char *cp, void *pin)
│           0x55fdbfcb319c      8945f4         mov dword [var_ch], eax
│           0x55fdbfcb319f      bf00000000     mov edi, 0
└           0x55fdbfcb31a4      e8a7feffff     call sym.imp.exit       ; void exit(int status)
[0x55fdbfcb3155]> 
```
First of all, the ip address is loaded as an ascii string in memory inside var_10h
```
[0x55fdbfcb3197]> dr rdi
0x55fdbfcb4004
[0x55fdbfcb3197]> pxw @ 0x55fdbfcb4004
0x55fdbfcb4004  0x312e3836 0x312e3837 0x312e3735 0x00003233  68.178.157.132..
```
Then, after the call, our variable is updated like this:
```
[0x55fdbfcb319c]> pxw @ 0x7ffc84ca8590
0x7ffc84ca8590  0x849db244 0x00007ffc 0x4fde3400 0xd921b956  D........4.OV.!.
```
And here we sii that 68.178.157.132 is represented as 0x849db244 in network byte order!

Feel free to check it using this calculator here: https://ncalculators.com/digital-computation/ip-address-hex-decimal-binary.htm

Knowing about the network byte order is important, specially if you are doing malware analysis as when working with some of those so called "indicators of compromise" network byte order needs to be taken into account as some malware can hardcode values like those for C&C/Data Exfiltration related stuff through sockets.

#### Main networking syscalls in Unix

##### Socket

To perform network I/O, the first thing a process must do is, call the socket function, specifying the type of communication protocol desired and protocol family, etc.
It'll work like this

```c
#include <sys/types.h>
#include <sys/socket.h>

int socket (int family, int type, int protocol);
```
It will return a socket descriptor, same thing as a file descriptor it will be an identifier for the socket, write/read calls will be able to be done on it. Family can mainly be AF_INET and AF_INET6 for ipv4/ipv6 connections, other connections can be made but are less common and we won't talk about them here. Type can be SOCK_STREAM, DGRAM, RAW, SEQPACKET will talk about them on the example, and finally protocol will commonly be IPPROTO_TCP/UDP. I assume you know about the fundamentals of networking.

##### Connect
This call connects a (tcp) socket to a (tcp) server
```c
#include <sys/types.h>
#include <sys/socket.h>

int connect(int sockfd, struct sockaddr *serv_addr, int addrlen);
```
We enter the socket file descriptor and then a socket address for the server (corresponding to the sockaddr struct: ip and port in network byte order) along with its lenght.

It will return 0 if everything worked fine.

##### Bind

The bind function assigns a local protocol address to a socket. With the Internet protocols, the protocol address is the combination of either a 32-bit IPv4 address or a 128-bit IPv6 address, along with a 16-bit TCP or UDP port number. This function is called by TCP server only.

```c
#include <sys/types.h>
#include <sys/socket.h>

int bind(int sockfd, struct sockaddr *my_addr,int addrlen);
```
Parameters are the same as the previous function, will return 0 if it has sucessfully binded to the adress.

##### Listen
The listen function performs two actions and it is called on the server it:

- Converts an unconnected socket into a passive socket (the one that is waiting for connections) indicating that the kernel should accept incomming connections directed to the socket
- Accepts a limited number of connections, indicated in the second parameter
```c
#include <sys/types.h>
#include <sys/socket.h>

int listen(int sockfd,int backlog);
```
Parameters are obvious, it will return 0 on success.

##### Accept
The accept function is called by a TCP server to return the next completed connection from the front of the completed connection queue. It allows us to start communicating with a client.
```c
#include <sys/types.h>
#include <sys/socket.h>

int accept (int sockfd, struct sockaddr *cliaddr, socklen_t *addrlen);
```
This call returns a non-negative descriptor on success, otherwise it returns -1 on error. The returned descriptor is assumed to be a client socket descriptor and all read-write operations will be done on this descriptor to communicate with the client.

##### Send
The send function is used to send data over stream sockets or CONNECTED datagram sockets. If you want to send data over UNCONNECTED datagram sockets, you must use sendto() function.

You can use write() system call that we have previously seen to send data by writting to the socket.

```C
int send(int sockfd, const void *msg, int len, int flags);
```
Parameters are the socket file descriptor, a pointer to a buffer containing the bytes you wanna send, the lenght of those and some flags that will be set to zero.

##### Recv
The recv function is used to receive data over stream sockets or CONNECTED datagram sockets. If you want to receive data over UNCONNECTED datagram sockets you must use recvfrom(). And this time yes, you can use read to get the content.
```c
int recv(int sockfd, void *buf, int len, unsigned int flags);
```
It works the same

We also have to close() function that will close the socket virtually eliminating it.

#### The server

Here I present you the very very basic server program written in C using unix network related syscalls. You will find this example on many tutorials but I think it is pretty fundamental to get it right before moving into something more complex, everythig that relates to networking will be somewhow built on top of this, so if you get this well you almost have it all.
```C
#include <stdio.h>
#include <stdlib.h>

#include <netdb.h>
#include <netinet/in.h>

#include <string.h>

int main( int argc, char *argv[] ) {
   int sockfd, newsockfd, portno, clilen;
   char buffer[256];
   struct sockaddr_in serv_addr, cli_addr;
   int  n;
   
   /* First call to socket() function */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }
   
   /* Initialize socket structure */
   bzero((char *) &serv_addr, sizeof(serv_addr)); // bzero initializes the data with zeros
   portno = 5001;
   
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);
   
   /* Now bind the host address using bind() call.*/
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR on binding");
      exit(1);
   }
      
   /* Now start listening for the clients, here process will
      * go in sleep mode and will wait for the incoming connection
   */
   
   listen(sockfd,5);
   clilen = sizeof(cli_addr);
   
   /* Accept actual connection from the client */
   newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
	
   if (newsockfd < 0) {
      perror("ERROR on accept");
      exit(1);
   }
   
   /* If connection is established then start communicating */
   bzero(buffer,256);
   n = read( newsockfd,buffer,255 );
   
   if (n < 0) {
      perror("ERROR reading from socket");
      exit(1);
   }
   
   printf("Here is the message: %s\n",buffer);
   
   /* Write a response to the client */
   n = write(newsockfd,"I got your message",18);
   
   if (n < 0) {
      perror("ERROR writing to socket");
      exit(1);
   }
      
   return 0;
}
```

So the program is simple, it is a server that will start listening and accepting connections at any address on port 5001 on the local machine, after a new connection it will read a message and write another one, then close.

Let's jump into radare2

```
[0x5595c1faa1d5]> pdf
            ; DATA XREF from entry0 @ 0x5595c1faa10d
┌ 539: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_160h @ rbp-0x160
│           ; var int64_t var_154h @ rbp-0x154
│           ; var int64_t var_144h @ rbp-0x144
│           ; var int64_t var_140h @ rbp-0x140
│           ; var int64_t var_13ch @ rbp-0x13c
│           ; var int64_t var_138h @ rbp-0x138
│           ; var int64_t var_134h @ rbp-0x134
│           ; var int64_t var_130h @ rbp-0x130
│           ; var int64_t var_12eh @ rbp-0x12e
│           ; var int64_t var_12ch @ rbp-0x12c
│           ; var int64_t var_120h @ rbp-0x120
│           ; var int64_t var_110h @ rbp-0x110
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x5595c1faa1d5      55             push rbp
│           0x5595c1faa1d6      4889e5         mov rbp, rsp
│           0x5595c1faa1d9      4881ec600100.  sub rsp, 0x160
│           0x5595c1faa1e0      89bdacfeffff   mov dword [var_154h], edi ; argc
│           0x5595c1faa1e6      4889b5a0feff.  mov qword [var_160h], rsi ; argv
│           0x5595c1faa1ed      64488b042528.  mov rax, qword fs:[0x28]
│           0x5595c1faa1f6      488945f8       mov qword [var_8h], rax
│           0x5595c1faa1fa      31c0           xor eax, eax
│           0x5595c1faa1fc      ba00000000     mov edx, 0
│           0x5595c1faa201      be01000000     mov esi, 1
│           0x5595c1faa206      bf02000000     mov edi, 2
│           0x5595c1faa20b      e8c0feffff     call sym.imp.socket     ; int socket(int domain, int type, int protocol)
│           0x5595c1faa210      8985c0feffff   mov dword [var_140h], eax
│           0x5595c1faa216      83bdc0feffff.  cmp dword [var_140h], 0
│       ┌─< 0x5595c1faa21d      7916           jns 0x5595c1faa235
│       │   0x5595c1faa21f      488d3dde0d00.  lea rdi, str.ERROR_opening_socket ; 0x5595c1fab004 ; "ERROR opening socket"
│       │   0x5595c1faa226      e875feffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5595c1faa22b      bf01000000     mov edi, 1
│       │   0x5595c1faa230      e88bfeffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5595c1faa235      488d85d0feff.  lea rax, [var_130h]
│           0x5595c1faa23c      48c700000000.  mov qword [rax], 0
│           0x5595c1faa243      48c740080000.  mov qword [rax + 8], 0
│           0x5595c1faa24b      c785c4feffff.  mov dword [var_13ch], 0x1389
│           0x5595c1faa255      66c785d0feff.  mov word [var_130h], 2
│           0x5595c1faa25e      c785d4feffff.  mov dword [var_12ch], 0
│           0x5595c1faa268      8b85c4feffff   mov eax, dword [var_13ch]
│           0x5595c1faa26e      0fb7c0         movzx eax, ax
│           0x5595c1faa271      89c7           mov edi, eax
│           0x5595c1faa273      e8d8fdffff     call sym.imp.htons
│           0x5595c1faa278      668985d2feff.  mov word [var_12eh], ax
│           0x5595c1faa27f      488d8dd0feff.  lea rcx, [var_130h]
│           0x5595c1faa286      8b85c0feffff   mov eax, dword [var_140h]
│           0x5595c1faa28c      ba10000000     mov edx, 0x10           ; 16
│           0x5595c1faa291      4889ce         mov rsi, rcx
│           0x5595c1faa294      89c7           mov edi, eax
│           0x5595c1faa296      e8f5fdffff     call sym.imp.bind       ; int bind(int socket, struct sockaddr*address, socklen_t address_len)
│           0x5595c1faa29b      85c0           test eax, eax
│       ┌─< 0x5595c1faa29d      7916           jns 0x5595c1faa2b5
│       │   0x5595c1faa29f      488d3d730d00.  lea rdi, str.ERROR_on_binding ; 0x5595c1fab019 ; "ERROR on binding"
│       │   0x5595c1faa2a6      e8f5fdffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5595c1faa2ab      bf01000000     mov edi, 1
│       │   0x5595c1faa2b0      e80bfeffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5595c1faa2b5      8b85c0feffff   mov eax, dword [var_140h]
│           0x5595c1faa2bb      be05000000     mov esi, 5
│           0x5595c1faa2c0      89c7           mov edi, eax
│           0x5595c1faa2c2      e8b9fdffff     call sym.imp.listen
│           0x5595c1faa2c7      c785bcfeffff.  mov dword [var_144h], 0x10 ; 16
│           0x5595c1faa2d1      488d95bcfeff.  lea rdx, [var_144h]
│           0x5595c1faa2d8      488d8de0feff.  lea rcx, [var_120h]
│           0x5595c1faa2df      8b85c0feffff   mov eax, dword [var_140h]
│           0x5595c1faa2e5      4889ce         mov rsi, rcx
│           0x5595c1faa2e8      89c7           mov edi, eax
│           0x5595c1faa2ea      e8c1fdffff     call sym.imp.accept
│           0x5595c1faa2ef      8985c8feffff   mov dword [var_138h], eax
│           0x5595c1faa2f5      83bdc8feffff.  cmp dword [var_138h], 0
│       ┌─< 0x5595c1faa2fc      7916           jns 0x5595c1faa314
│       │   0x5595c1faa2fe      488d3d250d00.  lea rdi, str.ERROR_on_accept ; 0x5595c1fab02a ; "ERROR on accept"
│       │   0x5595c1faa305      e896fdffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5595c1faa30a      bf01000000     mov edi, 1
│       │   0x5595c1faa30f      e8acfdffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5595c1faa314      488d85f0feff.  lea rax, [var_110h]
│           0x5595c1faa31b      4889c6         mov rsi, rax
│           0x5595c1faa31e      b800000000     mov eax, 0
│           0x5595c1faa323      ba20000000     mov edx, 0x20           ; 32
│           0x5595c1faa328      4889f7         mov rdi, rsi
│           0x5595c1faa32b      4889d1         mov rcx, rdx
│           0x5595c1faa32e      f348ab         rep stosq qword [rdi], rax
│           0x5595c1faa331      488d8df0feff.  lea rcx, [var_110h]
│           0x5595c1faa338      8b85c8feffff   mov eax, dword [var_138h]
│           0x5595c1faa33e      baff000000     mov edx, 0xff           ; 255
│           0x5595c1faa343      4889ce         mov rsi, rcx
│           0x5595c1faa346      89c7           mov edi, eax
│           0x5595c1faa348      b800000000     mov eax, 0
│           0x5595c1faa34d      e81efdffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x5595c1faa352      8985ccfeffff   mov dword [var_134h], eax
│           0x5595c1faa358      83bdccfeffff.  cmp dword [var_134h], 0
│       ┌─< 0x5595c1faa35f      7916           jns 0x5595c1faa377
│       │   0x5595c1faa361      488d3dd20c00.  lea rdi, str.ERROR_reading_from_socket ; 0x5595c1fab03a ; "ERROR reading from socket"
│       │   0x5595c1faa368      e833fdffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5595c1faa36d      bf01000000     mov edi, 1
│       │   0x5595c1faa372      e849fdffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5595c1faa377      488d85f0feff.  lea rax, [var_110h]
│           0x5595c1faa37e      4889c6         mov rsi, rax
│           0x5595c1faa381      488d3dcc0c00.  lea rdi, str.Here_is_the_message:__s ; 0x5595c1fab054 ; "Here is the message: %s\n"
│           0x5595c1faa388      b800000000     mov eax, 0
│           0x5595c1faa38d      e8cefcffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5595c1faa392      8b85c8feffff   mov eax, dword [var_138h]
│           0x5595c1faa398      ba12000000     mov edx, 0x12           ; 18
│           0x5595c1faa39d      488d35c90c00.  lea rsi, str.I_got_your_message ; 0x5595c1fab06d ; "I got your message"
│           0x5595c1faa3a4      89c7           mov edi, eax
│           0x5595c1faa3a6      b800000000     mov eax, 0
│           0x5595c1faa3ab      e880fcffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│           0x5595c1faa3b0      8985ccfeffff   mov dword [var_134h], eax
│           0x5595c1faa3b6      83bdccfeffff.  cmp dword [var_134h], 0
│       ┌─< 0x5595c1faa3bd      7916           jns 0x5595c1faa3d5
│       │   0x5595c1faa3bf      488d3dba0c00.  lea rdi, str.ERROR_writing_to_socket ; 0x5595c1fab080 ; "ERROR writing to socket"
│       │   0x5595c1faa3c6      e8d5fcffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5595c1faa3cb      bf01000000     mov edi, 1
│       │   0x5595c1faa3d0      e8ebfcffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5595c1faa3d5      b800000000     mov eax, 0
│           0x5595c1faa3da      488b4df8       mov rcx, qword [var_8h]
│           0x5595c1faa3de      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x5595c1faa3e7      7405           je 0x5595c1faa3ee
│       │   0x5595c1faa3e9      e852fcffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x5595c1faa3ee      c9             leave
└           0x5595c1faa3ef      c3             ret
[0x5595c1faa1d5]> 
```

First of all the program creates a socket for streaming, ipv4:
```
           0x5595c1faa20b      e8c0feffff     call sym.imp.socket     ; int socket(int domain, int type, int protocol)
│           ;-- rip:
│           0x5595c1faa210 b    8985c0feffff   mov dword [var_140h], eax
│           0x5595c1faa216      83bdc0feffff.  cmp dword [var_140h], 0
│       ┌─< 0x5595c1faa21d      7916           jns 0x5595c1faa235
```
Socket will have 0x3 as socket descriptor:

```
[0x5595c1faa210]> dr eax
0x00000003
```

Then the serv_addr struct (sockaddr_in) will be initialized like this
```
│       └─> 0x5595c1faa235      488d85d0feff.  lea rax, [var_130h]
│           0x5595c1faa23c      48c700000000.  mov qword [rax], 0
│           0x5595c1faa243      48c740080000.  mov qword [rax + 8], 0
│           0x5595c1faa24b      c785c4feffff.  mov dword [var_13ch], 0x1389 ; rdi
│           0x5595c1faa255      66c785d0feff.  mov word [var_130h], 2
│           0x5595c1faa25e      c785d4feffff.  mov dword [var_12ch], 0
│           0x5595c1faa268      8b85c4feffff   mov eax, dword [var_13ch]
│           0x5595c1faa26e      0fb7c0         movzx eax, ax
│           0x5595c1faa271      89c7           mov edi, eax
│           0x5595c1faa273      e8d8fdffff     call sym.imp.htons
│           0x5595c1faa278      668985d2feff.  mov word [var_12eh], ax
│           ;-- rip:
│           0x5595c1faa27f b    488d8dd0feff.  lea rcx, [var_130h]
```
0x1389 corresponds to port 5001. And INADDR_ANY is commonly represented with a 0 as you see there.

Then bind is called, the progam sends the socket and the address along with the size as you can see (16)

```
│           0x5595c1faa286      8b85c0feffff   mov eax, dword [var_140h]
│           0x5595c1faa28c      ba10000000     mov edx, 0x10           ; 16
│           0x5595c1faa291      4889ce         mov rsi, rcx
│           0x5595c1faa294      89c7           mov edi, eax
│           0x5595c1faa296      e8f5fdffff     call sym.imp.bind       ; int bind(int socket, struct sockaddr*address, socklen_t address_len)
│           0x5595c1faa29b      85c0           test eax, eax
```
Zero is returned as everything went OK
``` 
[0x5595c1faa29b]> dr
rax = 0x00000000
```
Then the listen, it will listen for 5 connections on the socket that is now bind to an address
```
│       └─> 0x5595c1faa2b5      8b85c0feffff   mov eax, dword [var_140h]
│           0x5595c1faa2bb      be05000000     mov esi, 5
│           0x5595c1faa2c0      89c7           mov edi, eax
│           0x5595c1faa2c2      e8b9fdffff     call sym.imp.listen
```
After this point we should see how our machine is actually listening for connections on that port:
```
lab@hal9000:~/rev/socket$ netstat -putona | grep "5001"
tcp        0      0 0.0.0.0:5001            0.0.0.0:*               LISTEN    19351/./server       off (0.00/0/0)
```
The next step? We have to accept connections on that socket, so we'll call accept() passing the socket that is listening as well as pointers to sockaddr. 
```
│           0x5595c1faa2c7      c785bcfeffff.  mov dword [var_144h], 0x10 ; rdx
│           0x5595c1faa2d1      488d95bcfeff.  lea rdx, [var_144h]
│           0x5595c1faa2d8      488d8de0feff.  lea rcx, [var_120h]
│           0x5595c1faa2df      8b85c0feffff   mov eax, dword [var_140h]
│           0x5595c1faa2e5      4889ce         mov rsi, rcx
│           0x5595c1faa2e8      89c7           mov edi, eax
│           0x5595c1faa2ea      e8c1fdffff     call sym.imp.accept
│           0x5595c1faa2ef      8985c8feffff   mov dword [var_138h], eax
│           0x5595c1faa2f5      83bdc8feffff.  cmp dword [var_138h], 0
```
It will return a new socket descriptor.

Then as we'll be reading from there with read() syscall we need to make some room for the message, look at this:

```
│           0x5595c1faa31e      b800000000     mov eax, 0
│           0x5595c1faa323      ba20000000     mov edx, 0x20           ; 32
│           0x5595c1faa328      4889f7         mov rdi, rsi
│           0x5595c1faa32b      4889d1         mov rcx, rdx
│           0x5595c1faa32e      f348ab         rep stosq qword [rdi], rax
│           0x5595c1faa331      488d8df0feff.  lea rcx, [var_110h]
│           0x5595c1faa338      8b85c8feffff   mov eax, dword [var_138h]
```
that rep instruction along with rax(=0x0) wil fill that structure with 0s, so will repeat moving zeroes there until done (https://docs.oracle.com/cd/E19455-01/806-3773/instructionset-64/index.html)

Then read will read from the socket.
```
│           0x5595c1faa331      488d8df0feff.  lea rcx, [var_110h]
│           0x5595c1faa338      8b85c8feffff   mov eax, dword [var_138h]
│           0x5595c1faa33e      baff000000     mov edx, 0xff           ; rdx
│           0x5595c1faa343      4889ce         mov rsi, rcx
│           0x5595c1faa346      89c7           mov edi, eax
│           0x5595c1faa348      b800000000     mov eax, 0
│           0x5595c1faa34d      e81efdffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
```
As we can see, the new socket descriptor will be send
```
[0x5595c1faa352]> pxw @ 0x7ffd85c18908
0x7ffd85c18908  0x00000004 0x00007fc3 0x89130002 0x00000000  ................
```
This is interesting as on the previous tutorials we used a descriptor refered to a file, now we are refering to something on the network, write does the same.

And we can see the contents.
```
[0x5595c1faa352]> afvd
[...]
var var_110h = 0x7ffd85c18930 = (qword)0x554c424b49545241
[0x5595c1faa352]> pxw @ 0x7ffd85c18930
0x7ffd85c18930  0x49545241 0x554c424b 0x00000a45 0x00000000  ARTIKBLUE.......
```
And then the program ends by doing the write on that new socket
```
│           0x5595c1faa392      8b85c8feffff   mov eax, dword [var_138h]
│           0x5595c1faa398      ba12000000     mov edx, 0x12           ; rdx
│           0x5595c1faa39d      488d35c90c00.  lea rsi, str.I_got_your_message ; 0x5595c1fab06d ; "I got your message"
│           0x5595c1faa3a4      89c7           mov edi, eax
│           0x5595c1faa3a6      b800000000     mov eax, 0
│           ;-- rip:
│           0x5595c1faa3ab b    e880fcffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
```
As you can see, same socket is used here, this time for write. This is also an important concept as this new socket created when accept()ing the connection is now a stream socket associated with an actual communication, it is the communication channel between the two machines.

#### The client

Meanwhile on the client...

Let's now explore the client progam for that server

```c
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char *argv[]) {
   int sockfd, portno, n;
   struct sockaddr_in serv_addr;
   struct hostent *server;
   
   char buffer[256];
   
   if (argc < 3) {
      fprintf(stderr,"usage %s hostname port\n", argv[0]);
      exit(0);
   }
   portno = atoi(argv[2]);
   /* Create a socket point */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }
	
   server = gethostbyname(argv[1]);
   
   if (server == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      exit(0);
   }
   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
   serv_addr.sin_port = htons(portno);
   /* Now connect to the server */
   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR connecting");
      exit(1);
   }
   
   /* Now ask for a message from the user, this message
      * will be read by server
   */
   printf("Please enter the message: ");
   bzero(buffer,256);
   fgets(buffer,255,stdin);
   
   /* Send message to the server */
   n = write(sockfd, buffer, strlen(buffer));
   
   if (n < 0) {
      perror("ERROR writing to socket");
      exit(1);
   }
   
   /* Now read server response */
   bzero(buffer,256);
   n = read(sockfd, buffer, 255);
   if (n < 0) {
      perror("ERROR reading from socket");
      exit(1);
   }
	
   printf("%s\n",buffer);
   return 0;
}
```
Again, this is another of those examples you can find anywhere in the internet, what it does is very simple and very similar to the server. It creates a socket connects it to the remote server on a ip:port then sends a message and waits for a response.


Here's the disasm
```
[0x563973801235]> pdf
            ; DATA XREF from entry0 @ 0x56397380116d
┌ 715: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x563973801235      55             push rbp
│           0x563973801236      4889e5         mov rbp, rsp
│           0x563973801239      4881ec500100.  sub rsp, 0x150
│           0x563973801240      89bdbcfeffff   mov dword [var_144h], edi ; argc
│           0x563973801246      4889b5b0feff.  mov qword [var_150h], rsi ; argv
│           0x56397380124d      64488b042528.  mov rax, qword fs:[0x28]
│           0x563973801256      488945f8       mov qword [var_8h], rax
│           0x56397380125a      31c0           xor eax, eax
│           0x56397380125c      83bdbcfeffff.  cmp dword [var_144h], 2
│       ┌─< 0x563973801263      7f2f           jg 0x563973801294
│       │   0x563973801265      488b85b0feff.  mov rax, qword [var_150h]
│       │   0x56397380126c      488b10         mov rdx, qword [rax]
│       │   0x56397380126f      488b05ca2d00.  mov rax, qword [reloc.stderr] ; [0x563973804040:8]=0
│       │   0x563973801276      488d35870d00.  lea rsi, str.usage__s_hostname_port ; 0x563973802004 ; "usage %s hostname port\n"
│       │   0x56397380127d      4889c7         mov rdi, rax
│       │   0x563973801280      b800000000     mov eax, 0
│       │   0x563973801285      e836feffff     call sym.imp.fprintf    ; int fprintf(FILE *stream, const char *format,   ...)
│       │   0x56397380128a      bf00000000     mov edi, 0
│       │   0x56397380128f      e86cfeffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x563973801294      488b85b0feff.  mov rax, qword [var_150h]
│           0x56397380129b      4883c010       add rax, 0x10           ; 16
│           0x56397380129f      488b00         mov rax, qword [rax]
│           0x5639738012a2      4889c7         mov rdi, rax
│           0x5639738012a5      e846feffff     call sym.imp.atoi       ; int atoi(const char *str)
│           0x5639738012aa      8985ccfeffff   mov dword [var_134h], eax
│           0x5639738012b0      ba00000000     mov edx, 0
│           0x5639738012b5      be01000000     mov esi, 1
│           0x5639738012ba      bf02000000     mov edi, 2
│           0x5639738012bf      e86cfeffff     call sym.imp.socket     ; int socket(int domain, int type, int protocol)
│           0x5639738012c4      8985d0feffff   mov dword [var_130h], eax
│           0x5639738012ca      83bdd0feffff.  cmp dword [var_130h], 0
│       ┌─< 0x5639738012d1      7916           jns 0x5639738012e9
│       │   0x5639738012d3      488d3d420d00.  lea rdi, str.ERROR_opening_socket ; 0x56397380201c ; "ERROR opening socket"
│       │   0x5639738012da      e801feffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5639738012df      bf01000000     mov edi, 1
│       │   0x5639738012e4      e817feffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5639738012e9      488b85b0feff.  mov rax, qword [var_150h]
│           0x5639738012f0      4883c008       add rax, 8
│           0x5639738012f4      488b00         mov rax, qword [rax]
│           0x5639738012f7      4889c7         mov rdi, rax
│           0x5639738012fa      e8b1fdffff     call sym.imp.gethostbyname
│           0x5639738012ff      488985d8feff.  mov qword [var_128h], rax
│           0x563973801306      4883bdd8feff.  cmp qword [var_128h], 0
│       ┌─< 0x56397380130e      752a           jne 0x56397380133a
│       │   0x563973801310      488b05292d00.  mov rax, qword [reloc.stderr] ; [0x563973804040:8]=0
│       │   0x563973801317      4889c1         mov rcx, rax
│       │   0x56397380131a      ba14000000     mov edx, 0x14           ; 20
│       │   0x56397380131f      be01000000     mov esi, 1
│       │   0x563973801324      488d3d060d00.  lea rdi, str.ERROR__no_such_host ; 0x563973802031 ; "ERROR, no such host\n"
│       │   0x56397380132b      e8f0fdffff     call sym.imp.fwrite     ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│       │   0x563973801330      bf00000000     mov edi, 0
│       │   0x563973801335      e8c6fdffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x56397380133a      488d85e0feff.  lea rax, [var_120h]
│           0x563973801341      48c700000000.  mov qword [rax], 0
│           0x563973801348      48c740080000.  mov qword [rax + 8], 0
│           0x563973801350      66c785e0feff.  mov word [var_120h], 2
│           0x563973801359      488b85d8feff.  mov rax, qword [var_128h]
│           0x563973801360      8b4014         mov eax, dword [rax + 0x14]
│           0x563973801363      4863d0         movsxd rdx, eax
│           0x563973801366      488b85d8feff.  mov rax, qword [var_128h]
│           0x56397380136d      488b4018       mov rax, qword [rax + 0x18]
│           0x563973801371      488b00         mov rax, qword [rax]
│           0x563973801374      488d8de0feff.  lea rcx, [var_120h]
│           0x56397380137b      4883c104       add rcx, 4
│           0x56397380137f      4889c6         mov rsi, rax
│           0x563973801382      4889cf         mov rdi, rcx
│           0x563973801385      e846fdffff     call sym.imp.memmove    ; void *memmove(void *s1, const void *s2, size_t n)
│           0x56397380138a      8b85ccfeffff   mov eax, dword [var_134h]
│           0x563973801390      0fb7c0         movzx eax, ax
│           0x563973801393      89c7           mov edi, eax
│           0x563973801395      e8d6fcffff     call sym.imp.htons
│           0x56397380139a      668985e2feff.  mov word [var_11eh], ax
│           0x5639738013a1      488d8de0feff.  lea rcx, [var_120h]
│           0x5639738013a8      8b85d0feffff   mov eax, dword [var_130h]
│           0x5639738013ae      ba10000000     mov edx, 0x10           ; 16
│           0x5639738013b3      4889ce         mov rsi, rcx
│           0x5639738013b6      89c7           mov edi, eax
│           0x5639738013b8      e853fdffff     call sym.imp.connect    ; ssize_t connect(int socket, void *addr, size_t addrlen)
│           0x5639738013bd      85c0           test eax, eax
│       ┌─< 0x5639738013bf      7916           jns 0x5639738013d7
│       │   0x5639738013c1      488d3d7e0c00.  lea rdi, str.ERROR_connecting ; 0x563973802046 ; "ERROR connecting"
│       │   0x5639738013c8      e813fdffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5639738013cd      bf01000000     mov edi, 1
│       │   0x5639738013d2      e829fdffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5639738013d7      488d3d790c00.  lea rdi, str.Please_enter_the_message: ; 0x563973802057 ; "Please enter the message: "
│           0x5639738013de      b800000000     mov eax, 0
│           0x5639738013e3      e898fcffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5639738013e8      488d85f0feff.  lea rax, [var_110h]
│           0x5639738013ef      4889c6         mov rsi, rax
│           0x5639738013f2      b800000000     mov eax, 0
│           0x5639738013f7      ba20000000     mov edx, 0x20           ; 32
│           0x5639738013fc      4889f7         mov rdi, rsi
│           0x5639738013ff      4889d1         mov rcx, rdx
│           0x563973801402      f348ab         rep stosq qword [rdi], rax
│           0x563973801405      488b15142c00.  mov rdx, qword [reloc.stdin] ; [0x563973804020:8]=0
│           0x56397380140c      488d85f0feff.  lea rax, [var_110h]
│           0x563973801413      beff000000     mov esi, 0xff           ; 255
│           0x563973801418      4889c7         mov rdi, rax
│           0x56397380141b      e880fcffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
│           0x563973801420      488d85f0feff.  lea rax, [var_110h]
│           0x563973801427      4889c7         mov rdi, rax
│           0x56397380142a      e821fcffff     call sym.imp.strlen     ; size_t strlen(const char *s)
│           0x56397380142f      4889c2         mov rdx, rax
│           0x563973801432      488d8df0feff.  lea rcx, [var_110h]
│           0x563973801439      8b85d0feffff   mov eax, dword [var_130h]
│           0x56397380143f      4889ce         mov rsi, rcx
│           0x563973801442      89c7           mov edi, eax
│           0x563973801444      b800000000     mov eax, 0
│           0x563973801449      e8f2fbffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
│           0x56397380144e      8985d4feffff   mov dword [var_12ch], eax
│           0x563973801454      83bdd4feffff.  cmp dword [var_12ch], 0
│       ┌─< 0x56397380145b      7916           jns 0x563973801473
│       │   0x56397380145d      488d3d0e0c00.  lea rdi, str.ERROR_writing_to_socket ; 0x563973802072 ; "ERROR writing to socket"
│       │   0x563973801464      e877fcffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x563973801469      bf01000000     mov edi, 1
│       │   0x56397380146e      e88dfcffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x563973801473      488d85f0feff.  lea rax, [var_110h]
│           0x56397380147a      4889c6         mov rsi, rax
│           0x56397380147d      b800000000     mov eax, 0
│           0x563973801482      ba20000000     mov edx, 0x20           ; 32
│           0x563973801487      4889f7         mov rdi, rsi
│           0x56397380148a      4889d1         mov rcx, rdx
│           0x56397380148d      f348ab         rep stosq qword [rdi], rax
│           0x563973801490      488d8df0feff.  lea rcx, [var_110h]
│           0x563973801497      8b85d0feffff   mov eax, dword [var_130h]
│           0x56397380149d      baff000000     mov edx, 0xff           ; 255
│           0x5639738014a2      4889ce         mov rsi, rcx
│           0x5639738014a5      89c7           mov edi, eax
│           0x5639738014a7      b800000000     mov eax, 0
│           0x5639738014ac      e8dffbffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x5639738014b1      8985d4feffff   mov dword [var_12ch], eax
│           0x5639738014b7      83bdd4feffff.  cmp dword [var_12ch], 0
│       ┌─< 0x5639738014be      7916           jns 0x5639738014d6
│       │   0x5639738014c0      488d3dc30b00.  lea rdi, str.ERROR_reading_from_socket ; 0x56397380208a ; "ERROR reading from socket"
│       │   0x5639738014c7      e814fcffff     call sym.imp.perror     ; void perror(const char *s)
│       │   0x5639738014cc      bf01000000     mov edi, 1
│       │   0x5639738014d1      e82afcffff     call sym.imp.exit       ; void exit(int status)
│       └─> 0x5639738014d6      488d85f0feff.  lea rax, [var_110h]
│           0x5639738014dd      4889c7         mov rdi, rax
│           0x5639738014e0      e84bfbffff     call sym.imp.puts       ; int puts(const char *s)
│           0x5639738014e5      b800000000     mov eax, 0
│           0x5639738014ea      488b75f8       mov rsi, qword [var_8h]
│           0x5639738014ee      644833342528.  xor rsi, qword fs:[0x28]
│       ┌─< 0x5639738014f7      7405           je 0x5639738014fe
│       │   0x5639738014f9      e862fbffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x5639738014fe      c9             leave
└           0x5639738014ff      c3             ret
[0x563973801235]> 
```
Let's now inspect the program.

Again as when dealing with many large progams, a smart approach is to focus on relevant syscalls analyzing their contexts

Let's start with socket()
```
│           0x5639738012b0      ba00000000     mov edx, 0
│           0x5639738012b5      be01000000     mov esi, 1
│           0x5639738012ba      bf02000000     mov edi, 2
│           0x5639738012bf      e86cfeffff     call sym.imp.socket     ; int socket(int domain, int type, int protocol)
``` 
As usual, we define a AF_INET, SOCK_STREAM socket
```
[0x55bd5654d2c4]> dr rax
0x00000003
```
And we get the socket descriptor as usual

Then we have this:
```
│       └─> 0x55bd5654d2e9      488b85b0feff.  mov rax, qword [var_150h]
│           0x55bd5654d2f0      4883c008       add rax, 8
│           0x55bd5654d2f4      488b00         mov rax, qword [rax]
│           0x55bd5654d2f7      4889c7         mov rdi, rax
│           0x55bd5654d2fa      e8b1fdffff     call sym.imp.gethostbyname
```
Gethostbyname (returns a structure of type hostent for the given host name) will read something like 127.0.0.1 ascii and return a network compatbile struct.

```
[0x55bd5654d2fa]> dr
rax = 0x7ffd9295a32f

[0x55bd5654d2fa]> pxw @ 0x7ffd9295a32f
0x7ffd9295a32f  0x2e373231 0x2e302e30 0x30350031 0x53003130  127.0.0.1.5001.S
```

After that it will set up the struct for the server address (sockaddr_in) by making use of the data returned by gethostbyname()

```
│           0x55bd5654d341      48c700000000.  mov qword [rax], 0
│           0x55bd5654d348      48c740080000.  mov qword [rax + 8], 0
│           0x55bd5654d350      66c785e0feff.  mov word [var_120h], 2
│           0x55bd5654d359      488b85d8feff.  mov rax, qword [var_128h]
│           0x55bd5654d360      8b4014         mov eax, dword [rax + 0x14]
│           0x55bd5654d363      4863d0         movsxd rdx, eax
│           0x55bd5654d366      488b85d8feff.  mov rax, qword [var_128h]
│           0x55bd5654d36d      488b4018       mov rax, qword [rax + 0x18]
│           0x55bd5654d371      488b00         mov rax, qword [rax]
│           0x55bd5654d374      488d8de0feff.  lea rcx, [var_120h]
│           0x55bd5654d37b      4883c104       add rcx, 4
│           0x55bd5654d37f      4889c6         mov rsi, rax
│           0x55bd5654d382      4889cf         mov rdi, rcx
│           0x55bd5654d385      e846fdffff     call sym.imp.memmove    ; void *memmove(void *s1, const void *s2, size_t n)
```
After that htons is called for the port
```
│           0x55bd5654d38a b    8b85ccfeffff   mov eax, dword [var_134h]
│           0x55bd5654d390      0fb7c0         movzx eax, ax
│           0x55bd5654d393      89c7           mov edi, eax
│           0x55bd5654d395      e8d6fcffff     call sym.imp.htons
│           ;-- rip:
│           0x55bd5654d39a b    668985e2feff.  mov word [var_11eh], ax

[0x55bd5654d39a]> dr rax
0x00008913
```
So, 8913 corresponding to 5001dec

And now we see the connect()

```
│           0x55bd5654d3b8      e853fdffff     call sym.imp.connect    ; ssize_t connect(int socket, void *addr, size_t addrlen)
│           0x55bd5654d3bd      85c0           test eax, eax
```
The socket will be connected to the server, that will now accept() the connection.

Then the program, now connected to the remote server, will use write on the socket descriptor to send the message:
```
│           0x55bd5654d42f      4889c2         mov rdx, rax
│           0x55bd5654d432      488d8df0feff.  lea rcx, [var_110h]
│           0x55bd5654d439      8b85d0feffff   mov eax, dword [var_130h]
│           0x55bd5654d43f      4889ce         mov rsi, rcx
│           0x55bd5654d442      89c7           mov edi, eax
│           0x55bd5654d444      b800000000     mov eax, 0
│           0x55bd5654d449      e8f2fbffff     call sym.imp.write      ; ssize_t write(int fd, const char *ptr, size_t nbytes)
```

Later on on the code, it will read from the input after making some space in a buffer as we saw in the server:
```
│           0x55bd5654d47a      4889c6         mov rsi, rax
│           0x55bd5654d47d      b800000000     mov eax, 0
│           0x55bd5654d482      ba20000000     mov edx, 0x20           ; 32
│           0x55bd5654d487      4889f7         mov rdi, rsi
│           0x55bd5654d48a      4889d1         mov rcx, rdx
│           0x55bd5654d48d      f348ab         rep stosq qword [rdi], rax
│           0x55bd5654d490      488d8df0feff.  lea rcx, [var_110h]
│           0x55bd5654d497      8b85d0feffff   mov eax, dword [var_130h]
│           0x55bd5654d49d      baff000000     mov edx, 0xff           ; 255
│           0x55bd5654d4a2      4889ce         mov rsi, rcx
│           0x55bd5654d4a5      89c7           mov edi, eax
│           0x55bd5654d4a7      b800000000     mov eax, 0
│           0x55bd5654d4ac      e8dffbffff     call sym.imp.read       ; ssize_t read(int fildes, void *buf, size_t nbyte)
```

```
0x7ffd92958e50  0x89130002 0x0100007f 0x00000000 0x00000000  ................
0x7ffd92958e60  0x6f672049 0x6f792074 0x6d207275 0x61737365  I got your messa
0x7ffd92958e70  0x00006567 0x00000000 0x00000000 0x00000000  ge..............
``` 

That's it for today. We'll go on a second part of this to show more advanced stuff like for example how malware makes use of this to implement C&C mechanisms via forging GET/DNS requests. We'll also see how to deal with this stuff on windows.

Stay tuned!