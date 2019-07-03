---
layout: post
title:	"x86 Assembly #4: Appending text to a file"
date:	2019-07-03 00:00:00
categories:
    - blog
tags:
    - linux
    - nasm
    - x86
    - objdump
    - ld
---
Today we are gonna write some assembly code that appends text to a file we choose. For this case we use two linux kernel syscalls:
 - calling open();  save file descriptor and pass it to `write`() syscall.
 - calling write()


{% highlight nasm %}
; appends text to a file we choose
global _start
section .text
_start:
        ; int open(const char *pathname, int flags)
        ; ssize_t write(int fd, const void *buf, size_t count)
        ; write - #4
        ; open  - #5

        ; call open() syscall
        mov eax, 0x5
        mov ebx, filename
        mov ecx, 0x401     ; 0x401 = (O_WRONLY | O_APPEND)
        int 0x80           ; Interrupt

        ; call write() syscall
        mov esi, eax       ; save file descriptor into esi register
        xor eax, eax       ; clear out eax register
        mov eax, 0x4
        mov ebx, esi       ; pass file descriptor
        mov ecx, data_to_write
        mov edx, len       ; pass length of the string
        int 0x80

        ; call exit(0) syscall
        xor eax, eax
        mov eax, 0x1
        mov ebx, 0x0
        int 0x80
section .data
        filename: db "text.txt",0x00
        data_to_write: db "Hello There",0x0a,0x00
        len equ $-data_to_write
{% endhighlight %}

To make sure this program calls syscalls we intend to call, use `strace` tool which gets all syscall calls from binary programs:
~~~
root@ubuntu:~/appending# strace ./appending 
execve("./appending", ["./appending"], [/* 24 vars */]) = 0
open("text.txt", O_WRONLY|O_APPEND)     = 3
write(3, "Hello There\n\0", 13)         = 13
exit(0)                                 = ?
+++ exited with 0 +++
root@ubuntu:~/appending# 
~~~