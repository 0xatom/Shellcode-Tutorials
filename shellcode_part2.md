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

This will be useful now, let's continue.

# 0x03 Removing null opcodes


