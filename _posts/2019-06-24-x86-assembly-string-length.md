---
layout: post
title:	"x86 Assembly #3: Calculate string length and call printf"
date:	2019-06-24 01:00:00
categories:
    - blog
tags:
    - linux
    - nasm
    - x86
    - objdump
    - ld
---
We're gonna write some assembly code to calcualte length of string and call printf to print out result. Final code is looking like this:
{% highlight nasm %}
; Calculate length of string
global main
extern printf  ;  printf is defined in libc library

section .text
main:
    xor esi, esi         ; esi = 0
    mov ecx, message     ; ecx -> message

loop:
    cmp byte [ecx], 0x0a
    je print
    mov al, byte [ecx]   ; copy byte by byte from message
    inc esi              ; increment counter esi
    inc ecx              ; increment pointer to message
    cmp al, 0x0a         ; test string termination
    jne loop             ; If not the end of string jump up to loop label

; printf("Length: %d", esi)
print:
    push esi             ; counter
    push format          ; pass address of format specifier
    call printf
    add esp,8            ; clean stack

    mov eax,0x1          ; exit(0) syscall
    xor ebx,ebx
    int 0x80

section .data
    format: db "Length: %d", 0x0a, 0x00
    message: db "Hello World", 0x0a, 0x00
{% endhighlight %}

First of all, we need to create counter, that simply keeps amount of character read so far:
~~~
xor esi, esi
mov ecx, message
~~~

and `ecx` register points to "`Hello World`" string
~~~
ecx ---->>>> |"Hello World"|
~~~

We create the loop and it keeps running until byte: `0x0a` is met. Then we arrange `printf` function arguments.
We push 2 arguments
 - esi
 - "Length: %d"

~~~
esp -> ["Length: %d" | esi]
~~~

Finally we call `exit(0)` syscall and program exits

Compiling and linking via `gcc`:
~~~
root@ubuntu:~/string-len# nasm -f elf32 str-len.asm -o str-len.o                                                 
root@ubuntu:~/string-len# gcc -o str-len str-len.o
root@ubuntu:~/string-len# ./str-len
Length: 11
root@ubuntu:~/string-len# 
~~~