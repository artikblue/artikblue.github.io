---
layout: post
title:  Reverse engineering 32 and 64 bits binaries with Radare2 - 12 (linked lists, enums, bitwise operations and r2pipe)
tags: reversing c radare
image: '/images//radare2/radare2_12.png'
date: 2020-05-11 15:01:35 -0700
---
Hello everybody!

We are about to end this first part of the course, aren't you excited? I'm sure you are.

Today we will be finally done with dynamic memory after studying linked lists, then we will jump to another topic and review bitwise operations, a very simple but important topic, very present in many programs.


#### Linked lists
As far as we know, everytime we need to work with multiple succesive data inputs we need to either define limits or ask the user about how many values is going to enter, it does not matter if the memory is dynamic or static, fas far as we know the user needs to specify the number of values to enter... What if we want the user to keep adding new values untill the end of time (memory)? 

Linked lists are an easy way to solve that. As far as we know, we can create structs of any type so, what if we create a struct containing a pointer to another struct? Everytime we add a new value we'll update the previous struct to make it point to the next creating a chain! We can store a reference to the "previous" struct while the user is entering values, after all is done, we'll only need a reference to the first element to loop through all of them.

```
// Linked list implementation in C

#include <stdio.h>
#include <stdlib.h>

// Creating a node
struct node {
  int data;
  struct node *next;
};

// print the linked list data
void printLinkedlist(struct node *p) {
  while (p != NULL) {
    printf("%d ", p->data);
    p = p->next;
  }
}

int main() {
  // Initialize nodes
  struct node *head;
  struct node *one = NULL;
  struct node *two = NULL;
  struct node *three = NULL;

  // Allocate memory
  one = malloc(sizeof(struct node));
  two = malloc(sizeof(struct node));
  three = malloc(sizeof(struct node));

  // Assign data values
  one->data = 1;
  two->data = 2;
  three->data = 3;

  // Connect nodes
  one->next = two;
  two->next = three;
  three->next = NULL;

  // printing node-data
  head = one;
  printLinkedlist(head);
}
```
As you can see, three nodes are being created and then linked at the end. Note that the node struct contains a pointer to a node struct, that may sound strange to you as the node struct has not been completely declared and it is already referencing its type, just know that it can be done, no problem. Also note that NULL can be used as an END value, we'll see what NULL means internally.

```
[0x5558a1d96182]> pdf
            ; DATA XREF from entry0 @ 0x5558a1d9607d
┌ 167: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_8h @ rbp-0x8
│           0x5558a1d96182      55             push rbp
│           0x5558a1d96183      4889e5         mov rbp, rsp
│           0x5558a1d96186      4883ec20       sub rsp, 0x20
│           0x5558a1d9618a      48c745e00000.  mov qword [var_20h], 0
│           0x5558a1d96192      48c745e80000.  mov qword [var_18h], 0
│           0x5558a1d9619a      48c745f00000.  mov qword [var_10h], 0
│           0x5558a1d961a2      bf10000000     mov edi, 0x10           ; 16
│           0x5558a1d961a7      e894feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x5558a1d961ac      488945e0       mov qword [var_20h], rax
│           0x5558a1d961b0      bf10000000     mov edi, 0x10           ; 16
│           0x5558a1d961b5      e886feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x5558a1d961ba      488945e8       mov qword [var_18h], rax
│           0x5558a1d961be      bf10000000     mov edi, 0x10           ; 16
│           0x5558a1d961c3      e878feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x5558a1d961c8      488945f0       mov qword [var_10h], rax
│           0x5558a1d961cc      488b45e0       mov rax, qword [var_20h]
│           0x5558a1d961d0      c70001000000   mov dword [rax], 1
│           0x5558a1d961d6      488b45e8       mov rax, qword [var_18h]
│           0x5558a1d961da      c70002000000   mov dword [rax], 2
│           0x5558a1d961e0      488b45f0       mov rax, qword [var_10h]
│           0x5558a1d961e4      c70003000000   mov dword [rax], 3
│           0x5558a1d961ea      488b45e0       mov rax, qword [var_20h]
│           0x5558a1d961ee      488b55e8       mov rdx, qword [var_18h]
│           0x5558a1d961f2      48895008       mov qword [rax + 8], rdx
│           0x5558a1d961f6      488b45e8       mov rax, qword [var_18h]
│           0x5558a1d961fa      488b55f0       mov rdx, qword [var_10h]
│           0x5558a1d961fe      48895008       mov qword [rax + 8], rdx
│           0x5558a1d96202      488b45f0       mov rax, qword [var_10h]
│           0x5558a1d96206      48c740080000.  mov qword [rax + 8], 0
│           0x5558a1d9620e      488b45e0       mov rax, qword [var_20h]
│           0x5558a1d96212      488945f8       mov qword [var_8h], rax
│           0x5558a1d96216      488b45f8       mov rax, qword [var_8h]
│           0x5558a1d9621a      4889c7         mov rdi, rax
│           0x5558a1d9621d      e823ffffff     call sym.printLinkedlist
│           0x5558a1d96222      b800000000     mov eax, 0
│           0x5558a1d96227      c9             leave
└           0x5558a1d96228      c3             ret
[0x5558a1d96182]> 
```
The program begins by keeping 32 bytes in the stack for variables as you can see here, then three variables are being initialized with zero, what do they mean? why are those being initialized to zero?
```
│           0x5558a1d96186      4883ec20       sub rsp, 0x20
│           0x5558a1d9618a      48c745e00000.  mov qword [var_20h], 0
│           0x5558a1d96192      48c745e80000.  mov qword [var_18h], 0
│           0x5558a1d9619a      48c745f00000.  mov qword [var_10h], 0
```
If we don't know about the original code, at this exact point we can't tell if those vars are just ints or whatever, but as we know about the original code we can quickly relate those to our initial node initialization with NULL, so those vars will reference our nodes (structs).

Then malloc is called with those three vars:
```
│           0x5558a1d961a2      bf10000000     mov edi, 0x10           ; 16
│           0x5558a1d961a7      e894feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x5558a1d961ac      488945e0       mov qword [var_20h], rax
│           0x5558a1d961b0      bf10000000     mov edi, 0x10           ; 16
│           0x5558a1d961b5      e886feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x5558a1d961ba      488945e8       mov qword [var_18h], rax
│           0x5558a1d961be      bf10000000     mov edi, 0x10           ; 16
│           0x5558a1d961c3      e878feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
```
Malloc keeps 16 bytes for each node, count 4 bytes for the int and at least 8 bytes more for the struct pointer, it also keeps a bit more space for that. The base addresses of those are kept in the previously NULL initialized vars.

Let's proceed
```
           0x5558a1d961cc      488b45e0       mov rax, qword [var_20h]
│           0x5558a1d961d0      c70001000000   mov dword [rax], 1
│           0x5558a1d961d6      488b45e8       mov rax, qword [var_18h]
│           0x5558a1d961da      c70002000000   mov dword [rax], 2
│           0x5558a1d961e0      488b45f0       mov rax, qword [var_10h]
│           0x5558a1d961e4      c70003000000   mov dword [rax], 3
```
At this point the INT var value of those structs is getting initialized to 1,2,3. Note that here [rax] is used, that means that var_20h, 18, 10 store POINTERS to STRUCT. At the previous part of the code, the POINTER was set to NULL, not the value, that is important. A null pointer == pointer that points to 0x0 is considered NULL and can be easily identified.

The next part of the code actually links those structs by the use of pointers:
```
│           0x5558a1d961ea      488b45e0       mov rax, qword [var_20h]
│           0x5558a1d961ee      488b55e8       mov rdx, qword [var_18h]
│           0x5558a1d961f2      48895008       mov qword [rax + 8], rdx
│           0x5558a1d961f6      488b45e8       mov rax, qword [var_18h]
│           0x5558a1d961fa      488b55f0       mov rdx, qword [var_10h]
│           0x5558a1d961fe      48895008       mov qword [rax + 8], rdx
│           0x5558a1d96202      488b45f0       mov rax, qword [var_10h]
│           0x5558a1d96206      48c740080000.  mov qword [rax + 8], 0
```
So, as you can see as each *next var is a pointer so the program just copies the addr of the pointed var there, easy. Also note that +8 is used here, that is because the pointer goes right after the int in the var. 

Then a weird thing is done for passing the first pointer as an argument to printLinkedList
```
│           0x5558a1d9620e      488b45e0       mov rax, qword [var_20h]
│           0x5558a1d96212      488945f8       mov qword [var_8h], rax
│           0x5558a1d96216      488b45f8       mov rax, qword [var_8h]
│           0x5558a1d9621a      4889c7         mov rdi, rax
│           0x5558a1d9621d      e823ffffff     call sym.printLinkedlist
```
Let's inspect that function.

```
[0x5558a1d96145]> pdf
            ; CALL XREF from main @ 0x5558a1d9621d
┌ 61: sym.printLinkedlist (int64_t arg1);
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int64_t arg1 @ rdi
│           0x5558a1d96145      55             push rbp
│           0x5558a1d96146      4889e5         mov rbp, rsp
│           0x5558a1d96149      4883ec10       sub rsp, 0x10
│           0x5558a1d9614d      48897df8       mov qword [var_8h], rdi ; arg1
│       ┌─< 0x5558a1d96151      eb25           jmp 0x5558a1d96178
│      ┌──> 0x5558a1d96153      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x5558a1d96157      8b00           mov eax, dword [rax]
│      ╎│   0x5558a1d96159      89c6           mov esi, eax
│      ╎│   0x5558a1d9615b      488d3da20e00.  lea rdi, [0x5558a1d97004] ; "%d "
│      ╎│   0x5558a1d96162      b800000000     mov eax, 0
│      ╎│   0x5558a1d96167      e8c4feffff     call sym.imp.printf     ; int printf(const char *format)
│      ╎│   0x5558a1d9616c      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x5558a1d96170      488b4008       mov rax, qword [rax + 8]
│      ╎│   0x5558a1d96174      488945f8       mov qword [var_8h], rax
│      ╎│   ; CODE XREF from sym.printLinkedlist @ 0x5558a1d96151
│      ╎└─> 0x5558a1d96178      48837df800     cmp qword [var_8h], 0
│      └──< 0x5558a1d9617d      75d4           jne 0x5558a1d96153
│           0x5558a1d9617f      90             nop
│           0x5558a1d96180      c9             leave
└           0x5558a1d96181      c3             ret
[0x5558a1d96145]> 
```
Inside printLinkedList, the argument (pointer) passed through rdi is loaded inside the local variable created by the compiler: var_8h
```
│           0x5558a1d9614d      48897df8       mov qword [var_8h], rdi ; arg1
│       ┌─< 0x5558a1d96151      eb25           jmp 0x5558a1d96178
│      ┌──> 0x5558a1d96153      488b45f8       mov rax, qword [var_8h]
```
Then the progam enters inside the loop and this is what it does: 
```
|      ┌──> 0x5558a1d96153      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x5558a1d96157      8b00           mov eax, dword [rax]
│      ╎│   0x5558a1d96159      89c6           mov esi, eax
│      ╎│   0x5558a1d9615b      488d3da20e00.  lea rdi, [0x5558a1d97004] ; "%d "
│      ╎│   0x5558a1d96162      b800000000     mov eax, 0
│      ╎│   0x5558a1d96167      e8c4feffff     call sym.imp.printf     ; int printf(const char *format)
│      ╎│   0x5558a1d9616c      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x5558a1d96170      488b4008       mov rax, qword [rax + 8]
│      ╎│   0x5558a1d96174      488945f8       mov qword [var_8h], rax
```
The contents of what is pointed by var_8h (pointer to struct) is loaded inside eax and then printed. After that, the magic happens. The pointer of the ACTUAL node is loaded inside rax, then added by 8 (pointer), and loaded again inside var_8h, in other terms, var_8h is a pointer to the actua node and by doing that +8 we load the contents of the next node inside the actual node struct inside the varible.
```
│      ╎│   ; CODE XREF from sym.printLinkedlist @ 0x5558a1d96151
│      ╎└─> 0x5558a1d96178      48837df800     cmp qword [var_8h], 0
│      └──< 0x5558a1d9617d      75d4           jne 0x5558a1d96153
```
The comparision (exit condition) of the loop is done at the end, comparing the POINTER with 0, as comparing a pointer with 0x0 then it means the pointer being compared to NULL.

And that's aaaaaaall with dynamic memory. I think you got the concept right, debug the program yourself as an exercise!


#### Discovering r2pipe

There may be situations when the code is complex, and the progam repeats actions or follows long patters of code before generating any interesting results. Other situations may include doing the exact same analysis multiple times under different input values, or doing the same analysis on many many binaries in batch. We may also want to calculate something, using the memory of the program, to reveal hidden features, discover bugs or interesting leaks or whatever.

In all of those situations, the solution comes with the usage of r2pipe.

r2pipe is kind of the r2 api. It let's us interact with r2 scripting in several programming languages such as python or javascript. On this example we are going to use r2pipe under python, for doing automatic analysis of a simple binary. We can install it using pip with:

```
pip3 install r2pipe
```
Then we start using r2pipe with:
```
import r2pipe
r = r2pipe.open('binary')
```
After that the r variable will be a link to r2pipe, doing r.cmd('aaa') will be the same as being in a r2 session and actually running the command "aaa". In r2 a lot of commands can be executed appending a "j" at the end, that "j" will turn the output into a json object making things easy for us when using r2pipe.

A typical hello world using r2pipe may be something like:

```
import r2pipe as r2
import json

r = r2.open('superlist')

r.cmd('aaa')
print(r.cmd('iL'))
print(r.cmd('afl'))
```

Let's now get hands on with it, consider the following:
```
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int randy(){
	int r = rand(); 

	return r % 20 + 5;

}

struct node {
  int i;
  struct node *next;
};


int main(){
	srand(time(NULL));   // Initialization, should only be called once.
	int ran = 0;

	struct node *ant; 
	struct node *first_node = NULL;

	first_node = malloc(sizeof(struct node));

	first_node->i = 1;
	ant = first_node;


	for(int i = 0; i < randy(); i++){

		struct node *actual;
		actual =  malloc(sizeof(struct node));
		actual->next = NULL;
		actual->i = randy();

		ant->next = actual;
		ant = actual;

	}

	return 0;
}
```
As you can see this program is a bit tricky. It initializes a dynamic linked list of N random elements, each element containing a random int + a pointer to the next element (NULL if last element). The tricky thing here is that, as you can see, on the program there is no printf call, at the end there is no way for the user to know about how many values the list does have and their content.

We can disasm the program like this:
```
            ; DATA XREF from entry0 @ 0x5582293f909d
┌ 171: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_1ch @ rbp-0x1c
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_8h @ rbp-0x8
│           0x5582293f919e      55             push rbp
│           0x5582293f919f      4889e5         mov rbp, rsp
│           0x5582293f91a2      4883ec20       sub rsp, 0x20
│           0x5582293f91a6      bf00000000     mov edi, 0
│           0x5582293f91ab      e890feffff     call sym.imp.time       ; time_t time(time_t *timer)
│           0x5582293f91b0      89c7           mov edi, eax
│           0x5582293f91b2      e879feffff     call sym.imp.srand      ; void srand(int seed)
│           0x5582293f91b7      c745e4000000.  mov dword [var_1ch], 0
│           0x5582293f91be      48c745f00000.  mov qword [var_10h], 0
│           0x5582293f91c6      bf10000000     mov edi, 0x10           ; 16
│           0x5582293f91cb      e880feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│           0x5582293f91d0      488945f0       mov qword [var_10h], rax
│           0x5582293f91d4      488b45f0       mov rax, qword [var_10h]
│           0x5582293f91d8      c70001000000   mov dword [rax], 1
│           0x5582293f91de      488b45f0       mov rax, qword [var_10h]
│           0x5582293f91e2      488945e8       mov qword [var_18h], rax
│           0x5582293f91e6      c745e0000000.  mov dword [var_20h], 0
│       ┌─< 0x5582293f91ed      eb44           jmp 0x5582293f9233
│      ┌──> 0x5582293f91ef      bf10000000     mov edi, 0x10           ; 16
│      ╎│   0x5582293f91f4      e857feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
│      ╎│   0x5582293f91f9      488945f8       mov qword [var_8h], rax
│      ╎│   0x5582293f91fd      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x5582293f9201      48c740080000.  mov qword [rax + 8], 0
│      ╎│   0x5582293f9209      b800000000     mov eax, 0
│      ╎│   0x5582293f920e      e852ffffff     call sym.randy
│      ╎│   0x5582293f9213      89c2           mov edx, eax
│      ╎│   0x5582293f9215      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x5582293f9219      8910           mov dword [rax], edx
│      ╎│   0x5582293f921b      488b45e8       mov rax, qword [var_18h]
│      ╎│   0x5582293f921f      488b55f8       mov rdx, qword [var_8h]
│      ╎│   0x5582293f9223      48895008       mov qword [rax + 8], rdx
│      ╎│   0x5582293f9227      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x5582293f922b      488945e8       mov qword [var_18h], rax
│      ╎│   0x5582293f922f      8345e001       add dword [var_20h], 1
│      ╎│   ; CODE XREF from main @ 0x5582293f91ed
│      ╎└─> 0x5582293f9233      b800000000     mov eax, 0
│      ╎    0x5582293f9238      e828ffffff     call sym.randy
│      ╎    0x5582293f923d      3945e0         cmp dword [var_20h], eax
│      └──< 0x5582293f9240      7cad           jl 0x5582293f91ef
│           0x5582293f9242      b800000000     mov eax, 0
│           0x5582293f9247      c9             leave
└           0x5582293f9248      c3             ret
[0x5582293f919e]> 
```
And as you can see the magic happens inside that loop there, the randy() function gets called and the program generates and links those nodes there, nothing new for us. Extracting all of those nodes manually may be tedious, we can set a breakpoint at the end of the function, then do afvd and use px or pf to inspect the memory, and so forth. As the list is dynamic and we don't have a fixed size if we go manually we'll have to set breakpoints on the first randy call to know how many values are up to be generated, again this can be slow and there is no need to do it manually, specially if need to do some kind of operation with those numbers, or we need to dump them many times to check for vuln research or whatever (I don't know, maybe a crypto attack?).

We can automate the whole thing using r2pipe. What I would do manually is (blindly): set a breakpoint where the first node is initialized and then at the end of the main where all of the nodes should be set and linked. Then I would inspect the first node, dump the value and note it, then extract the pointer to next, go there and repeat the process until the next pointer is 0x0 NULL, does that make sense? Another option my be: set a breakpoint after the initial randy call and, note how many nodes are going to be generted, set a breakpoint at the end of code and from there do a pf Ni..p or whatever but I will assume that those nodes may not be one right after the other in memory, so the first option makes more sense for me now.


Based on the logic we presented, I generated the following script with python using r2pipe. I'm not a professional developer so... the code just works and I think it is clear enough:

![rapper](https://static-s.aa-cdn.net/img/gp/20600004843148/6nzSMduRrevd8Zn9D6ldcy0E13toZ4ZB-LODfPwMrSoh4BDyhgOEOKYSBNHd-9is0A8=w300?v=1)

Here's the code:
```python
import r2pipe as r2
import json

r = r2.open('superlist')

r.cmd('doo; s main')

disasm = json.loads(r.cmd("pdj"))

# mov dword [rax], 1
print("[+] linked list initialization detected at: ")
print(str(hex(disasm[13]["offset"]))+" "+disasm[13]["disasm"])
list_base_addr = hex(disasm[13]["offset"])
print("[+] setting a breakpoint at: "+list_base_addr)
r.cmd('db '+str(list_base_addr))
r.cmd('dc')
initial_regs = json.loads(r.cmd('drj'))

list_first_node = initial_regs["rax"]

print("[+] list initial node base address: "+hex(list_first_node))

# leave
print("[+] end of the main function detected at")
print(str(hex(disasm[39]["offset"]))+" "+disasm[39]["disasm"])
main_end = hex(disasm[39]["offset"])
print("[+] setting a breakpoint at: "+main_end)
r.cmd('db '+str(main_end))
r.cmd('dc')
print("[+] the end of the program has been reached")
print("[+] parsing the list now")

node_int = json.loads(r.cmd('pfj i @ '+str(list_first_node)))

print("[+] int item val = "+str(node_int[0]["value"]))

next_addr = hex(int(list_first_node)+8)

node_pointer =  json.loads(r.cmd('pfj p @ '+str(next_addr)))
next_addr =  int(node_pointer[0]["value"])

print("[+] next node located @ "+ hex(node_pointer[0]["value"]))

while next_addr != 0:
	node_int = json.loads(r.cmd('pfj i @ '+str(hex(next_addr))))
	print("[+] int item val = "+str(node_int[0]["value"]))
	
	next_addr = hex(int(next_addr)+8)
	node_pointer =  json.loads(r.cmd('pfj p @ '+str(next_addr)))
	next_addr = int(node_pointer[0]["value"])
	print("[+] next node located @ "+ hex(node_pointer[0]["value"]))

print("[*] End Of List")
```
As you can see, there is no mystery here, just a bunch of r2 commands one after another, the key concept here is that we can implement our own logic to automate stuff.

Aaaand the script will output something like this:
```
Process with PID 23857 started...
= attach 23857 23857
File dbg:///home/lab/rev/superlist  reopened in read-write mode
[+] linked list initialization detected at: 
0x5591047661d8 mov dword [rax], 1
[+] setting a breakpoint at: 0x5591047661d8
hit breakpoint at: 5591047661d8
[+] list initial node base address: 0x559104c23260
[+] end of the main function detected at
0x559104766247 leave
[+] setting a breakpoint at: 0x559104766247
hit breakpoint at: 559104766247
[+] the end of the program has been reached
[+] parsing the list now
[+] int item val = 1
[+] next node located @ 0x559104c23280
[+] int item val = 20
[+] next node located @ 0x559104c232a0
[+] int item val = 21
[+] next node located @ 0x559104c232c0
[+] int item val = 6
[+] next node located @ 0x559104c232e0
[+] int item val = 19
[+] next node located @ 0x559104c23300
[+] int item val = 16
[+] next node located @ 0x559104c23320
[+] int item val = 16
[+] next node located @ 0x559104c23340
[+] int item val = 23
[+] next node located @ 0x559104c23360
[+] int item val = 15
[+] next node located @ 0x559104c23380
[+] int item val = 10
[+] next node located @ 0x0
[*] End Of List
``` 
The magic here is as we are exploring the list node by node untill we find a NULL pointer the size of the list does not matter at all. The distribution of the nodes in memory does not matter as well, as we will be following pointers, so we'll expect the program itself to tell us where the next node can be found. Whatever the size or the distribution are we will be able to extract all of the values, and I think that's wonderful. 

You should now compile the program and try it yourself.

We will now proceed exploring the mysteries of bit wise operations

#### Bitwise operations

![Bitwise](https://preview.redd.it/lwlhsfatbzo01.png?width=960&crop=smart&auto=webp&s=4761a110b7ab032c8777bea0cf99e5f03a649818)

Bitwise operations are so simple I assume you already know about basic logical operations such as and, or, xor. Let's look at this:
```
#include <stdio.h>
 
int main() {
    int a   = 67;
    int b   =  33;
 
    printf("var a = %d\n", a);
    printf("var b = %d\n\n", b);
    printf("  Complement of a = %d\n", ~a);
    printf("  a AND b = %d\n", a&b);
    printf("  a OR b =  %d\n", a|b);
    printf("  a XOR b = %d\n", a^b);
    printf("  A left shifted 1 = %d\n", a << 1);
    printf("  A right shifted 1 = %d\n", a >> 1);
    getchar();
    return 0;
    
}
```
The concept here is simple, just know that in C as well as in other many languages bitwise operations such as those can be easily made. Bitwise operations are present and actively used in some progams, we'll present a specific example after this first one.

Bitwise operations are mega easy to understand when disasm'ing a code because it is literally the same, it can be even easier to understand in the disasm, let's see:
```
[0x7fa9fae06090]> s main
[0x55d69499a145]> pdf
            ; DATA XREF from entry0 @ 0x55d69499a07d
┌ 225: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_4h @ rbp-0x4
│           0x55d69499a145      55             push rbp
│           0x55d69499a146      4889e5         mov rbp, rsp
│           0x55d69499a149      4883ec10       sub rsp, 0x10
│           0x55d69499a14d      c745f8430000.  mov dword [var_8h], 0x43 ; 'C' ; 67
│           0x55d69499a154      c745fc210000.  mov dword [var_4h], 0x21 ; '!' ; 33
│           0x55d69499a15b      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a15e      89c6           mov esi, eax
│           0x55d69499a160      488d3d9d0e00.  lea rdi, str.var_a____d ; 0x55d69499b004 ; "var a = %d\n"
│           0x55d69499a167      b800000000     mov eax, 0
│           0x55d69499a16c      e8bffeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55d69499a171      8b45fc         mov eax, dword [var_4h]
│           0x55d69499a174      89c6           mov esi, eax
│           0x55d69499a176      488d3d930e00.  lea rdi, str.var_b____d ; 0x55d69499b010 ; "var b = %d\n\n"
│           0x55d69499a17d      b800000000     mov eax, 0
│           0x55d69499a182      e8a9feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55d69499a187      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a18a      f7d0           not eax
│           0x55d69499a18c      89c6           mov esi, eax
│           0x55d69499a18e      488d3d880e00.  lea rdi, str.Complement_of_a____d ; 0x55d69499b01d ; "  Complement of a = %d\n"
│           0x55d69499a195      b800000000     mov eax, 0
│           0x55d69499a19a      e891feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55d69499a19f      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a1a2      2345fc         and eax, dword [var_4h]
│           0x55d69499a1a5      89c6           mov esi, eax
│           0x55d69499a1a7      488d3d870e00.  lea rdi, str.a_AND_b____d ; 0x55d69499b035 ; "  a AND b = %d\n"
│           0x55d69499a1ae      b800000000     mov eax, 0
│           0x55d69499a1b3      e878feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55d69499a1b8      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a1bb      0b45fc         or eax, dword [var_4h]
│           0x55d69499a1be      89c6           mov esi, eax
│           0x55d69499a1c0      488d3d7e0e00.  lea rdi, str.a_OR_b_____d ; 0x55d69499b045 ; "  a OR b =  %d\n"
│           0x55d69499a1c7      b800000000     mov eax, 0
│           0x55d69499a1cc      e85ffeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55d69499a1d1      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a1d4      3345fc         xor eax, dword [var_4h]
│           0x55d69499a1d7      89c6           mov esi, eax
│           0x55d69499a1d9      488d3d750e00.  lea rdi, str.a_XOR_b____d ; 0x55d69499b055 ; "  a XOR b = %d\n"
│           0x55d69499a1e0      b800000000     mov eax, 0
│           0x55d69499a1e5      e846feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55d69499a1ea      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a1ed      01c0           add eax, eax
│           0x55d69499a1ef      89c6           mov esi, eax
│           0x55d69499a1f1      488d3d6d0e00.  lea rdi, str.A_left_shifted_1____d ; 0x55d69499b065 ; "  A left shifted 1 = %d\n"
│           0x55d69499a1f8      b800000000     mov eax, 0
│           0x55d69499a1fd      e82efeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55d69499a202      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a205      d1f8           sar eax, 1
│           0x55d69499a207      89c6           mov esi, eax
│           0x55d69499a209      488d3d6e0e00.  lea rdi, str.A_right_shifted_1____d ; 0x55d69499b07e ; "  A right shifted 1 = %d\n"
│           0x55d69499a210      b800000000     mov eax, 0
│           0x55d69499a215      e816feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55d69499a21a      e821feffff     call sym.imp.getchar    ; int getchar(void)
│           0x55d69499a21f      b800000000     mov eax, 0
│           0x55d69499a224      c9             leave
└           0x55d69499a225      c3             ret
[0x55d69499a145]> 
```
The complement operation is the equiv of not, all zeros will turn ones and vice-versa, asm not works like this:
```
│           0x55d69499a187      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a18a      f7d0           not eax
│           0x55d69499a18c      89c6           mov esi, eax
│           0x55d69499a18e      488d3d880e00.  lea rdi, str.Complement_of_a____d ; 0x55d69499b01d ; "  Complement of a = %d\n"
```
And is also present in the x86/x64 instruction set:
```
│           0x55d69499a19f      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a1a2      2345fc         and eax, dword [var_4h]
│           0x55d69499a1a5      89c6           mov esi, eax
│           0x55d69499a1a7      488d3d870e00.  lea rdi, str.a_AND_b____d ; 0x55d69499b035 ; "  a AND b = %d\n"
```
As well as or
```
│           0x55d69499a1b8      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a1bb      0b45fc         or eax, dword [var_4h]
│           0x55d69499a1be      89c6           mov esi, eax
│           0x55d69499a1c0      488d3d7e0e00.  lea rdi, str.a_OR_b_____d ; 0x55d69499b045 ; "  a OR b =  %d\n"
```
And XOR, keep XOR very present as it is commonly used in shitty crypters/packers 
```
│           0x55d69499a1d1      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a1d4      3345fc         xor eax, dword [var_4h]
│           0x55d69499a1d7      89c6           mov esi, eax
│           0x55d69499a1d9      488d3d750e00.  lea rdi, str.a_XOR_b____d ; 0x55d69499b055 ; "  a XOR b = %d\n"
```
Shift operations can be used for multiplication/division in the scope of some algorithms. In asm, sar and sal can be used for shift aligns, but also adds and subs can be used as well:
```
│           0x55d69499a1ea      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a1ed      01c0           add eax, eax
│           0x55d69499a1ef      89c6           mov esi, eax
│           0x55d69499a1f1      488d3d6d0e00.  lea rdi, str.A_left_shifted_1____d ; 0x55d69499b065 ; "  A left shifted 1 = %d\n"

│           0x55d69499a202      8b45f8         mov eax, dword [var_8h]
│           0x55d69499a205      d1f8           sar eax, 1
│           0x55d69499a207      89c6           mov esi, eax
│           0x55d69499a209      488d3d6e0e00.  lea rdi, str.A_right_shifted_1____d ; 0x55d69499b07e ; "  A right shifted 1 = %d\n"
```


#### Enums
Remember global constant variables? 
```
#include <stdio.h>

enum week {Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday};

int main()
{
    // creating today variable of enum week type
    enum week today;
    today = Wednesday;
    printf("Day %d",today+1);
    return 0;
}
```
Enums are kind of lists of constant values, let's decompile that:
```
[0x55a7617a5135]> pdf
            ; DATA XREF from entry0 @ 0x55a7617a506d
┌ 47: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_4h @ rbp-0x4
│           0x55a7617a5135      55             push rbp
│           0x55a7617a5136      4889e5         mov rbp, rsp
│           0x55a7617a5139      4883ec10       sub rsp, 0x10
│           0x55a7617a513d      c745fc030000.  mov dword [var_4h], 3
│           0x55a7617a5144      8b45fc         mov eax, dword [var_4h]
│           0x55a7617a5147      83c001         add eax, 1
│           0x55a7617a514a      89c6           mov esi, eax
│           0x55a7617a514c      488d3db10e00.  lea rdi, str.Day__d     ; 0x55a7617a6004 ; "Day %d"
│           0x55a7617a5153      b800000000     mov eax, 0
│           0x55a7617a5158      e8d3feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55a7617a515d      b800000000     mov eax, 0
│           0x55a7617a5162      c9             leave
└           0x55a7617a5163      c3             ret
[0x55a7617a5135]> 
```
Those enums are auto indexed, so for example, Sunday will be represented as 0, Monday 1 and so forth, said that we can easily understand that Wednesday == 3. Now the program is easy to understand. Also note that, as those enus are 100% constant static structs, that is a thing that is directly passed to the compiler, the compiler then builds a program according to that (so everytime a compiler reads Wednesday it will just put a 3 there).

Enums are commonly used along with bitwise operations to pass flags to functions.
```
#include <stdio.h>

enum designFlags {
	BOLD = 1,
	ITALICS = 2,
	UNDERLINE = 4
};

int main() {
	int myDesign = BOLD | UNDERLINE; 

        //    
        //  | 
        //  ___________
        //    

	printf("%d", myDesign);

	return 0;
}
```
Imagine you have a function that already receives a lot of parameters, and you need even more parameters, such as permissions, format relatd stuff, access modes or whatever and those parameters can even go together, parameters can easily grow and make the code very hard to read. Enums along with bitwise operations can help with that.

Look at the previous example imagine passing BOLD as a parameter to a function, that would be something like: 00000001, but also imagine that you want your text bold as well as underline (as presented in the code), underline would be: 00000100, why pass those values? We can logically add them with an or and we'll get this: 00000101, that is 5. So if the function gets a five it will know that 5 can only be a combination of BOLD and UNDERLINE. Think about chmod, do you get it now?
```
[0x5560d3fdd135]> pdf
            ; DATA XREF from entry0 @ 0x5560d3fdd06d
┌ 44: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_4h @ rbp-0x4
│           0x5560d3fdd135      55             push rbp
│           0x5560d3fdd136      4889e5         mov rbp, rsp
│           0x5560d3fdd139      4883ec10       sub rsp, 0x10
│           0x5560d3fdd13d      c745fc050000.  mov dword [var_4h], 5
│           0x5560d3fdd144      8b45fc         mov eax, dword [var_4h]
│           0x5560d3fdd147      89c6           mov esi, eax
│           0x5560d3fdd149      488d3db40e00.  lea rdi, [0x5560d3fde004] ; "%d"
│           0x5560d3fdd150      b800000000     mov eax, 0
│           0x5560d3fdd155      e8d6feffff     call sym.imp.printf     ; int printf(const char *format)
│           0x5560d3fdd15a      b800000000     mov eax, 0
│           0x5560d3fdd15f      c9             leave
└           0x5560d3fdd160      c3             ret
[0x5560d3fdd135]> 
```
In this case, the compiler resolves the logical OR operation and directly introduces a 5 inside the var, cool!