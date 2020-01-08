# Introduction To Shellcoding

Im reading at the time a great book [The Shellcoder's Handbook: Discovering and Exploiting Security Holes](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X). I want to take my binary exploitation skills a step farther. Im writing this tutorial because i want to understand better what im reading/doing like a guy said "you think you understand something until you try to teach it" & because i want to use this as my personal "cheat sheet" if you get me. Let's begin!

Table of contents :
+ 0x01 What is shellcode ?
+ 0x02 System Calls + ASM Analysis
+ 0x03 Writing Shellcode for exit() Syscall

# 0x01 What is shellcode ?

Shellcode is our payload, lot of `\x**` characters together. For example `\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80` is a piece of shellcode which when executed will spawn a shell. If the vulnerable binary is SETUID will give us a root shell! 

Shellcode generally written in an assembler & translated into hexadecimal opcodes.

You cannot inject shellcode written from a high-level language like (python,ruby etc), because there are thing that will prevent shellcode from executing cleanly & give us shell for example. This is what makes writing shellcode hard.

Hope you now understand what shellcode really is. Let's move on.

# 0x02 System Calls + ASM Analysis

Things are getting a bit harder here. Basic ASM/Linux knowledge is must.

One way to control a program is to force it to make a system call(syscall). Syscalls are really powerful functions, that allow you to access operating system functions like : input, ouput, exit, execute. Syscalls allow you to directly access the kernel, which gives you access to low-level functions like reading and writing files. Syscalls are ways by which user mode interacts with the kernel mode.

You can get the list of the syscalls by executing : 
```bash
[root@pwn4magic]:~/Desktop# man syscalls
```

![syscalls](https://i.ibb.co/G0TBk65/syscalls.png)

There are 2 methods of executing a syscall in linux. You can use the C libc (library of standard functions) which works indirectly or execute directly with assembly.

The int 0x80 instruction call syscalls in linux. When int 0x80 is executed by a user mode program, CPU switches into kernel mode and executes the syscall.

The process :
1. The syscall number is loaded into EAX. (EAX Register stores the return value of a function)
2. Syscall function arguments are placed in other registers.
3. The instruction int 0x80 is executed.
4. The CPU switches to kernel mode.
5. The syscall function is executed.

Each syscall can have a maximum of six arguments, which placed into EBX, ECX, EDX, ESI, EDI, and EPB.

Now let's make a syscall in C & then disassemble the binary. So we can see the assembly instructions. The most basic syscall is exit() (cause normal process termination).

```C
#include <stdio.h>

main()
{
	exit(0);
}
```

Let's compile it now.

```bash
[root@pwn4magic]:~/Desktop# gcc -static -m32 -w exit.c -o exit
[root@pwn4magic]:~/Desktop# file exit
exit: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=db2e8edbbe52d0a8cf0c58777df3f8bccbd39990, for GNU/Linux 3.2.0, not stripped
[root@pwn4magic]:~/Desktop# ./exit 
```

I used the `-m32` option because i use 64bit OS. Now let's disassemble the binary.

```asm
[root@pwn4magic]:~/Desktop# gdb -q exit
Reading symbols from exit...
(No debugging symbols found in exit)
gdb-peda$ disassemble _exit
Dump of assembler code for function _exit:
   0x0806bf3a <+0>:	mov    ebx,DWORD PTR [esp+0x4]
   0x0806bf3e <+4>:	mov    eax,0xfc
   0x0806bf43 <+9>:	call   DWORD PTR gs:0x10
   0x0806bf4a <+16>:	mov    eax,0x1
   0x0806bf4f <+21>:	int    0x80
   0x0806bf51 <+23>:	hlt    
End of assembler dump.
gdb-peda$ 
```

We have 2 syscalls. The number of the syscall to be called is stored in EAX

```asm
0x0806bf3e <+4>:	mov    eax,0xfc
0x0806bf4a <+16>:	mov    eax,0x1
```

`0xfc = 252 = sys_exit_group`
`0x1  = 1   = 	sys_exit`

Then we have an instruction that loads the argument for our exit syscall into EBX.

```asm
0x0806bf3a <+0>:	mov    ebx,DWORD PTR [esp+0x4]
```

In the end, we have the the ```0x0806bf4f <+21>:	int    0x80``` instrunction, which switch the CPU to kernel mode.

# 0x03 Writing Shellcode for exit() Syscall

From a high level, our shellcode should do the following :
1. Store the value of 0 into EBX.
2. Store the value of 1 into EAX. 
3. Execute int 0x80 instruction to make the syscall.

Let's write it into assembly.

```asm
Section  .text

	global _start

_start:

	mov ebx,0
	mov eax,1
	int 0x80
```

Now let's build the executable.

First step is to use the nasm assembler to create our object file, and then the GNU linker to link object file.

```bash
[root@pwn4magic]:~/Desktop# nasm -f elf exit_shellcode.asm
[root@pwn4magic]:~/Desktop# ld -m elf_i386 exit_shellcode.o -o exit_shellcode
```

Now we're ready to take our opcodes. I use this small bash script.

```bash 
for i in `objdump -d exit_shellcode | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" ; done
```

```bash
[root@pwn4magic]:~/Desktop# for i in `objdump -d exit_shellcode | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" ; done
\xbb\x00\x00\x00\x00\xb8\x01\x00\x00\x00\xcd\x80
```

Now let's test our shellcode with a simple C program.

```C
#include <stdio.h>

char shellcode[] = "\xbb\x00\x00\x00\x00"
		   "\xb8\x01\x00\x00\x00"
		   "\xcd\x80";

int main()
{
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int)shellcode;
}
```

Compile with :

```bash
[root@pwn4magic]:~/Desktop# gcc -w -m32 -fno-stack-protector -z execstack test_shellcode.c -o test_shellcode
[root@pwn4magic]:~/Desktop# ./test_shellcode 
```

Now how can we be sure it was our shellcode ? Let's use a great tool called `strace` which intercepts syscalls.

```bash
[root@pwn4magic]:~/Desktop# strace ./test_shellcode
execve("./test_shellcode", ["./test_shellcode"], 0x7ffe8814f8d0 /* 52 vars */) = 0
strace: [ Process PID=27440 runs in 32 bit mode. ]
brk(NULL)                               = 0x5688d000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7f90000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=118613, ...}) = 0
mmap2(NULL, 118613, PROT_READ, MAP_PRIVATE, 3, 0) = 0xf7f73000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/lib32/libc.so.6", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0`\351\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1936972, ...}) = 0
mmap2(NULL, 1945548, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xf7d98000
mmap2(0xf7db5000, 1355776, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1d000) = 0xf7db5000
mmap2(0xf7f00000, 446464, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x168000) = 0xf7f00000
mmap2(0xf7f6d000, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1d4000) = 0xf7f6d000
mmap2(0xf7f71000, 8140, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xf7f71000
close(3)                                = 0
set_thread_area({entry_number=-1, base_addr=0xf7f910c0, limit=0x0fffff, seg_32bit=1, contents=0, read_exec_only=0, limit_in_pages=1, seg_not_present=0, useable=1}) = 0 (entry_number=12)
mprotect(0xf7f6d000, 8192, PROT_READ)   = 0
mprotect(0x565ec000, 4096, PROT_READ)   = 0
mprotect(0xf7fbe000, 4096, PROT_READ)   = 0
munmap(0xf7f73000, 118613)              = 0
exit(0)                                 = ?
+++ exited with 0 +++
```

At last line is our `exit(0)` syscall. :)

That's it hope you learned something, very soon i'll make the part2.
