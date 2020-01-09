# Removing null opcodes (\x00)
Let's continue now, we will learn how to remove the null opcodes. Basic Linux/ASM knowledge is must.

Table of contents :
+ 0x01 Why we need to remove the nulls ?
+ 0x02 Exclusive OR (XOR)
+ 0x03 Removing null opcodes

# 0x01 Why we need to remove the nulls ?

This is our shellcode (exit() syscall) from the previous tutorial : 
```
\xbb\x00\x00\x00\x00\xb8\x01\x00\x00\x00\xcd\x80
```

You notice that there are some null opcodes (\x00). These nulls will cause our shellcode to fail when injected, because the null character is used to terminate strings. We need to find a way to change our nulls into non-null opcodes.

# 0x02 Exclusive OR (XOR)

XOR is a binary operation, it means "Exclusive OR". If both bits are equal we put 0 else we put 1.

For example :

```
1001 0101 0011 1101
0101 0100 1101 0101
-------------------
1100 0001 1110 1000
```

Let's test it out with python.

```python
>>> 0 ^ 0
0
>>> 1 ^ 1
0
>>> 1 ^ 0
1
```

This will be useful later, let's continue.

# 0x03 Removing null opcodes

To remove the null opcodes, we have to simply replace assembly instructions that create nulls with other instructions that do not.

Let's take a look into our 3 assembly instructions from the previous tutorial :

```asm
mov ebx,0          \xbb\x00\x00\x00\x00          
mov eax,1          \xb8\x01\x00\x00\x00                  
int 0x80           \xcd\x80  
```

The first two instructions are responsible for creating the nulls. As we said before, if both bits are equal we put 0 else we put 1. This means that if we use the XOR instruction on two operands that we know are equal, we can get the value of 0 without having to use a value of 0 in an instruction.  

This means that we'll not have a null opcode. Instead of using the mov instruction to set the value of 0 to EBX, let’s use the XOR instruction. So : 

```asm
mov ebx,0 
will be :
xor ebx,ebx 
```
