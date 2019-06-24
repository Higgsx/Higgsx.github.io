---
layout: post
title:	"x86 Assembly #2: Turn 'Hello World' into shellcode"
date:	2019-06-24 01:00:00
categories:
    - blog
tags:
    - linux
    - nasm
    - x86
    - objdump
    - ld
    - shellcode
---
In previous blog post we wrote assembly code that simply prints "Hello World" string to stdout stream. In this blog post we are gonna turn this into shellcode "format".

First, Grab hex bytes via objdump command:
~~~
root@ubuntu:~/hello# objdump -d ./hello -M intel

./hello:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:       b8 04 00 00 00          mov    eax,0x4
 8048085:       bb 01 00 00 00          mov    ebx,0x1
 804808a:       b9 a4 90 04 08          mov    ecx,0x80490a4
 804808f:       ba 0e 00 00 00          mov    edx,0xe
 8048094:       cd 80                   int    0x80
 8048096:       b8 01 00 00 00          mov    eax,0x1
 804809b:       bb 00 00 00 00          mov    ebx,0x0
 80480a0:       cd 80                   int    0x80
~~~

We see NULL bytes,that we don't want to exist in our final shellcode, because of string terminations in C and C++. In order to remove null bytes we have to change some instructions. for example:

{% highlight nasm %}
mov eax,0x4  ; Becomes mov al,0x4
mov ebx,0x0  ; Becomes xor ebx,ebx
{% endhighlight %}

Final code will be something like that:
{% highlight nasm %}
; Hello_World shellcode
; Target: 32-bit Linux
; Syscall: ssize_t write(int fd, const void *buf, size_t count)
global _start

section .text
_start:
        mov al, 0x4          ; write() syscall number
        mov bl, 0x1          ; fd = 1(stdout)
        mov ecx, message      ; pointer to message
        mov dl, len           ; len(message)
        int 0x80                 ; interrupt; transition to kernel land

        ; exit(0) syscall
        mov al, 0x1      ; exit() syscall number
        xor ebx,ebx      ; 0 = SUCCESS
        int 0x80         ; interrupt; transition to kernel land

section .data
        message: db "Hello World!", 0x00, 0x0a
        len equ $-message
{% endhighlight %}

Let's see final result:
~~~
root@ubuntu:~/hello# nasm -f elf32 hello-nulls.asm -o hello-nulls.o
root@ubuntu:~/hello# ld hello-nulls.o -o hello-nulls
root@ubuntu:~/hello# ./hello-nulls 
Hello World!
root@ubuntu:~/hello# objdump -d ./hello-nulls -M intel

./hello-nulls:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:       b0 04                   mov    al,0x4
 8048082:       b3 01                   mov    bl,0x1
 8048084:       b9 94 90 04 08          mov    ecx,0x8049094
 8048089:       b2 0e                   mov    dl,0xe
 804808b:       cd 80                   int    0x80
 804808d:       b0 01                   mov    al,0x1
 804808f:       31 db                   xor    ebx,ebx
 8048091:       cd 80                   int    0x80
root@ubuntu:~/hello# 
~~~

We don't see any null bytes and that's good. Let's turn this into shellcode format via this command:
~~~
root@ubuntu:~/hello# objdump -d ./hello-nulls | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xb0\x04\xb3\x01\xb9\x94\x90\x04\x08\xb2\x0e\xcd\x80\xb0\x01\x31\xdb\xcd\x80"
~~~

Note: This command was copied from: `https://www.commandlinefu.com/commands/view/6051/get-all-shellcode-on-binary-file-from-objdump`

We need to test this via C code written below:
{% highlight c %}
#include <stdio.h>

unsigned char shellcode[] = "";
int main()
{
        void (*code)() = (void (*)())shellcode;
        code();
}
{% endhighlight %}
Currently we have 2 issue:
 - When shellcode is called from C code, registers we use(eax,ebx etc) is filled with some data, we need to get rid of.
 - We've static address: `0x8049094`.

We have to change assembly code somehow to address above mentioned issues:
{% highlight nasm %}
; Hello_World shellcode
; Target: 32-bit Linux
; Syscall: ssize_t write(int fd, const void *buf, size_t count)
global _start

section .text
_start:
        ; Zero out(clean) register
        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx

        mov al, 0x4     ; write() syscall number
        mov bl, 0x1     ; fd = 1(stdout)

        ; Push "Hello World!" bytes into the stack memory area
        push 0x0a          ; "!"
        push 0x21646c72
        push 0x6f57206f
        push 0x6c6c6548
        mov ecx,esp      ; pointer to message
        mov dl, 13     ; len("Hello World!")
        int 0x80                 ; interrupt; transition to kernel land

        ; exit(0) syscall
        xor eax, eax
        mov al, 0x1      ; exit() syscall number
        xor ebx,ebx      ; 0 = SUCCESS
        int 0x80         ; interrupt; transition to kernel land
{% endhighlight %}
Look at hex bytes via objdump
~~~
08048060 <_start>:
 8048060:       31 c0                   xor    eax,eax
 8048062:       31 db                   xor    ebx,ebx
 8048064:       31 c9                   xor    ecx,ecx
 8048066:       31 d2                   xor    edx,edx
 8048068:       b0 04                   mov    al,0x4
 804806a:       b3 01                   mov    bl,0x1
 804806c:       6a 0a                   push   0xa
 804806e:       68 72 6c 64 21          push   0x21646c72
 8048073:       68 6f 20 57 6f          push   0x6f57206f
 8048078:       68 48 65 6c 6c          push   0x6c6c6548
 804807d:       89 e1                   mov    ecx,esp
 804807f:       b2 0d                   mov    dl,0xd
 8048081:       cd 80                   int    0x80
 8048083:       31 c0                   xor    eax,eax
 8048085:       b0 01                   mov    al,0x1
 8048087:       31 db                   xor    ebx,ebx
 8048089:       cd 80                   int    0x80
~~~

Everything looks fine, we don't have null bytes and let's convert hex bytes into shellcode format with above mentioned `objdump` command. Insert bytes into C code, compile and test it.
{% highlight c %}
#include <stdio.h>

unsigned char shellcode[] = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\x6a\x0a\x68\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68\x48\x65\x6c\x6c\x89\xe1\xb2\x0d\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80";
int main()
{
        void (*code)() = (void (*)())shellcode;
        code();
}
{% endhighlight %}
~~~
root@ubuntu:~/hello# gcc test-shellcode.c -o test-shellcode
root@ubuntu:~/hello# ./test-shellcode 
Segmentation fault
root@ubuntu:~/hello# 
~~~

We got `Segmentation Fault`. Reason for this is that we placed shellcode into the stack and modern Compilers and Operating Systems denies machine instruction execition in stack memory area. This is called `NX(NoeXecute)` and `DEP(Data Execution Prevention)` in Windows systems. Disable this protection via gcc argument: `-z execstack`:
~~~
root@ubuntu:~/hello# gcc test-shellcode.c -o test-shellcode -z execstack
root@ubuntu:~/hello# ./test-shellcode 
Hello World!
root@ubuntu:~/hello#
~~~

So, our shellcode works fine and we can insert it anywhere on 32-bit linux systems.

H@ppy H@ck1ng!