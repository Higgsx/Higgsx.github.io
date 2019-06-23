---
layout: post
title:	"x86 Assembly #1: Hello World"
date:	2019-06-23 01:00:00
categories:
    - blog
tags:
    - linux
    - nasm
    - x86
    - objdump
    - ld
---
## Hello.asm
~~~
; Hello_World shellcode
; Target: 32-bit Linux
; Syscall: ssize_t write(int fd, const void *buf, size_t count)
global _start

section .text
_start:
    mov eax, 0x4     ; write() syscall number
    mov ebx, 0x1     ; fd = 1(stdout)
    mov ecx, message ; pointer to message
    mov edx, len     ; len(message)
    int 0x80         ; interrupt; transition to kernel land

    ; exit(0) syscall
    mov eax, 0x1     ; exit() syscall number
    mov ebx, 0x0     ; 0 = SUCCESS
    int 0x80         ; interrupt; transition to kernel land

section .data
    message: db "Hello World!", 0x00, 0x0a
    len equ $-message
~~~

First thing we have to get is numerical syscall number via unistd32.h:
~~~
root@ubuntu:~# locate unistd32
/usr/src/linux-headers-4.4.0-142/arch/arm64/include/asm/unistd32.h
root@ubuntu:~#
~~~

Open it and look at `write()` and `exit()` syscalls:
~~~
#define __NR_restart_syscall 0
__SYSCALL(__NR_restart_syscall, sys_restart_syscall)
#define __NR_exit 1
__SYSCALL(__NR_exit, sys_exit)
#define __NR_fork 2
__SYSCALL(__NR_fork, sys_fork)
#define __NR_read 3
__SYSCALL(__NR_read, sys_read)
#define __NR_write 4
__SYSCALL(__NR_write, sys_write)
#define __NR_open 5
__SYSCALL(__NR_open, compat_sys_open)
#define __NR_close 6
__SYSCALL(__NR_close, sys_close)
~~~

In this case I'm showing just `write()` syscall's number.

Compiling and linking hello.asm:
~~~
root@ubuntu:~/hello# nasm -f elf32 hello.asm -o hello.o
root@ubuntu:~/hello# ld hello.o -o hello
root@ubuntu:~/hello# ./hello
Hello World!
root@ubuntu:~/hello#
~~~