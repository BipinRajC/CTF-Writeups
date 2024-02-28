
### 1. Reykjavik

- we shall use `Cutter` which is a GUI based tool from `radare` which can `disassemble` and use `ghidra plugin` for decompiling binaries as well
> `./Cutter.AppImage` - then import the binary and in bottom use decompiler from ghidra (download cutter from [cutter installation](https://cutter.re/download/) 

```c
puVar1 = (uint8_t *)argv[1];
iVar2 = strcmp(&uStack_38, puVar1);
            if (iVar2 == 0) {
                __printf_chk(1, "Congratulations, you found the flag!!: \'%s\'\n\n", &uStack_38);
```
- this is the decompiled main code which is performing the check of the argument we pass with a value on the `stack`
- when we do `./Reykjavik` with no argument it gives us the correct usage which is `./Reykjavik CTFlearn{the_correct_flag}` and when we use it like this if the flag is right it will display saying congrats you've found it
- the equivalent code in assembly for the above one we get by hovering over the code , now we need to set a breakpoint here and analyze, we can do this using `gdb-pwndbg`
```c
0x00001168      call    strcmp     ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
```
The commands i ran in `gdb-pwndbg` were :
```
gdb-pwndbg --args Reykjavik CTFlearn{test_flag}
run
start
disass
b *0x0000555555555168
run
```
- when we do `start`, it will show until `main()` is encountered and then it stops and now, we do `disass` to disassemble `main()` function to see the `strcmp` offset and `set a breakpoint` there and look at the stack value being compared with the argument we provided.
> FLAG - `CTFlearn{Eye_L0ve_Iceland_}`
---
### 2. Basic Android RE 1

First thing, it's an `apk` file so we will have to use a `Java decompiler` to decompile this apk, and to do this we have 2 options, to use `jadx` by downloading it from [here](https://github.com/skylot/jadx) or by using the [online java decompiler](http://www.javadecompilers.com/apktool) 

So whenever we are dealing with RE, after disassembly/decompile we always go out on the look for the `main function` or the `Main Activity`, the same case here as well.
on opening the apk file on the online java decompiler, we get 2 folders `resources` and `sources` and by just going and exploring we find out the location of 
`BasicAndroidRE1.apk/sources/com/example/secondapp/MainActivity.java` 

Here, we can clearly see an md5 hash being 1st part of flag after decoding from [md5decrypt](https://md5decrypt.net/en/) 
md5 hash = b74dec4f39d35b6a2e6c48e637c8aedb = Spring2019
> FLAG - `CTFlearn{Spring2019_is_not_secure!}`
---
### 3. Riyadh

first make it an executable by doing `chmod +x Riyadh` and run `strings` on it but we don't see anything interesting, now open it up on any disassembler like `ghidra`, `cutter` etc and anlayze the `main` function

like the prev qn, `Reykjavik` we do see a `strcmp` statement in the main function and when we run in `gdb-pwndbg` after setting `breakpoint` at the `strcmp`, we get a fake flag, so we change our approach, now what?
```c
0x0000555555555149 <+73>:    call   0x555555555d20 <_Z18CTFLearnHiddenFlagv>
   0x000055555555514e <+78>:    mov    r13,QWORD PTR [r13+0x8]
   0x0000555555555152 <+82>:    mov    rdi,rbp
   0x0000555555555155 <+85>:    call   0x5555555556f0 <_Z4Msg3Pc>
   0x000055555555515a <+90>:    mov    rdi,rbp
   0x000055555555515d <+93>:    mov    rsi,r13
   0x0000555555555160 <+96>:    call   0x5555555550e0 <strcmp@plt>
   0x0000555555555165 <+101>:   test   eax,eax
   0x0000555555555167 <+103>:   je     0x555555555286 <main+390>
   0x000055555555516d <+109>:   mov    rdi,r13
```

you can see different `msg` words like `msg1`, `msg2`, `msg3` and so on and they're basically different functions cuz we see them under the functions sections and when we jump into it, we see some `xor` operations so obfuscation and encryption of plain messages basically.

right after `msg1 statement` theres the `puts(buffer)` and then `puts("Compile Options: ${CMAKE_CXX_FLAGS} -O0 -fno-stack-protector -mno-sse");` 
From this we can kinda say that `msg1` was just the `greeting message` and likewise `msg2` was the `usage message` we get if we dont give proper argument to the executable
so on we can keep setting breakpoints at these `msg` function calls but these functions look like they take arguments, coz of the if conditions that need to be satisfied before the statements execute so now what we had to do was 

- before `msg5` was called, this condition had to be satisfied `if (iVar6 == 0x1e)` and `0x1e` when converted from hex to decimal is `30` so what we had to do was to give an argument to `msg5`'s breakpoint run as a `30 letter string`
> NOTE - the breakpoint shouldnt be right at the call because then the flow will stop right at the call and its function wont be executed, we need the result of that call so set the breakpoint just after
- here, after disassembly of main() in `pwn-dbg` we can see that we have to set breakpoint right after msg5 and it can be done as `b *main+151` and do `run aaaaabbbbbcccccdddddeeeeefffff` and we can see the flag
```c
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x0
*RBX  0x7fffffffdec8 —▸ 0x7fffffffe24e ◂— '/home/bipinraj/Downloads/Riyadh'
*RCX  0x13567
*RDX  0x55555556b6c0 ◂— 'CTFlearn{Masmak_Fortress_1865}'
*RDI  0x555555558070 (fmsg) ◂— 0x2508d01b7dc612d9
*RSI  0x555555558160 (xormask) ◂— 0x4b7ab17e1180469a
*R8   0x100
*R9   0x110
*R10  0x7ffff7c25dd0 ◂— 0xd001200002d1e
```
> FLAG - `CTFlearn{Masmak_Fortress_1865}` 
---
### 4. Rangoon

This program takes an argument of the flag and if it's correct, it gives a message indicating it was the right flag and if not, it gives an error message 
```c
    puVar4 = (uint8_t *)argv[1];
        iVar9 = 9;
        puVar11 = puVar4;
        puVar13 = (uint8_t *)"CTFlearn{";
        do {
            if (iVar9 == 0) break;
            iVar9 = iVar9 + -1;
            bVar16 = *puVar11 < *puVar13;
            bVar17 = *puVar11 == *puVar13;
            puVar11 = puVar11 + (uint64_t)uVar18 * -2 + 1;
            puVar13 = puVar13 + (uint64_t)uVar18 * -2 + 1;
        } while (bVar17);
```
the above block of decompiled code from `ghidra` tells us that the first 9 characters of the argument would be `CTFlearn{` which is obvious because that is the flag format.

Before the last `strcmp` there is a `cmp` in `register13(r13)` with value `0x1c=28` so it looks like the argument checks if it has 28 characters so we pass an argument of length 28 = `CTFlearn{aaaaaaaaaaaaaaaaaa}`
```c
0x00005555555552e2 <+418>:   call   0x555555555130 <__memcpy_chk@plt>
   0x00005555555552e7 <+423>:   add    r13,rax
   0x00005555555552ea <+426>:   cmp    r13,0x1c
   0x00005555555552ee <+430>:   jne    0x55555555536f <main+559>
   0x00005555555552f0 <+432>:   mov    rsi,rbp
   0x00005555555552f3 <+435>:   mov    rdi,r14
   0x00005555555552f6 <+438>:   call   0x555555555110 <strcmp@plt>
   0x00005555555552fb <+443>:   mov    r13d,eax
```

when we set a breakpoint at `cmp     r13,0x1c` and run the program we get :
```c
*RAX  0x5555555580fd (buffer+29) ◂— 0x7d /* '}' */
*RBX  0xe3
*RCX  0x7d
*RDX  0xfffffffffffffffe
*RDI  0x5555555580fd (buffer+29) ◂— 0x7d /* '}' */
*RSI  0x7d
*R8   0x400
*R9   0x5555555581df (buffer+255) ◂— 0x55555556b2b000
*R10  0x1000
*R11  0x202
*R12  0x55555556b2b0 —▸ 0x5555555560c1 ◂— 0x6c6c4100676e694b /* 'King' */
*R13  0x1e
*R14  0x7fffffffe26e ◂— 'CTFlearn{aaaaaaaaaaaaaaaaaa}'
*R15  0xc
*RBP  0x5555555580e0 (buffer) ◂— 'CTFlearn{Prince_Princess_Devi}'
*RSP  0x7fffffffdd70 ◂— 0x0
*RIP  0x5555555552ea (main+426) ◂— cmp r13, 0x1c
```

ivar9 stores length of arg and the next if condition checks if the last character of argument is `0x7d = }` , uvar2 and uvar3 are initialized to be `puVar4` (argument passed) index positions `0x11=17` & `0x16=22` respectively which are then checked to be `0x5f = _` 
```c
iVar9 = strlen(puVar4);
            if (puVar4[iVar9 + -1] == 0x7d) {
                uVar2 = puVar4[0x11];
                uVar3 = puVar4[0x16];
                uVar10 = 0xffffffffffffffff;
                pcVar14 = buffer;
                do {
                    if (uVar10 == 0) break;
                    uVar10 = uVar10 - 1;
                    cVar1 = *pcVar14;
                    pcVar14 = pcVar14 + (uint64_t)uVar18 * -2 + 1;
                } while (cVar1 != (code)0x0);
                uVar10 = ~uVar10;
                *(undefined8 *)(uVar10 + 0x40df) = 0x6e7261656c465443;
                iVar5 = _strings;
                *(undefined2 *)(uVar10 + 0x40e7) = 0x7b;
                iVar8 = __stpcpy_chk(uVar10 + 0x40e8, *(undefined8 *)(iVar5 + (uint64_t)((uVar2 == 0x5f) + 2) * 8), 
                                     (int64_t)puVar12 - (uVar10 + 0x40e8));
                iVar8 = __memcpy_chk(iVar8, data.0000200e, 2, (int64_t)puVar12 - iVar8);
                iVar8 = __stpcpy_chk(iVar8 + 1, *(undefined8 *)(iVar5 + ((uint64_t)(uVar3 == 0x5f) * 5 + 3) * 8), 
                                     (int64_t)data.000041df - iVar8);
```
 What happens here is that the program builds the flag, if you look with more attention you will notice three `__stpcpy_chk` calls and three `__memcpy_chk` calls which are similar to `strcpy` and `memcpy` commands 
 `__memcpy_chk` appends `_` into the string in the first two calls, and `}` in the last. `__strcpy__chk` appends a different word depending on the condition.

now from the info we know 1 thing, if we pass a flag arg wrapped in `CTFlearn{}` with length != 28 and we set breakpoint just before last strcmp we see that in r13 it compares with flag `CTFlearn{Prince_Princess_Thaketa}` and if we pass argument within `CTFlearn{}` with length = 28 and set break at same place, it compares with `CTFlearn{Prince_Princess_Devi}` 

we do know that at 17 & 22 there should be `_` (from index 0) 
when we do strings we find this 
```
I love Rangoon!
People's Square and Park
Kandawgyi Nature Park
Devi
Shwedagon Pagoda
Bago River
Thaketa
Maha
Alexander Fraser
Burma
Myanmar
Yangon
Princess
Prince
Queen
King
```
and we do have an idea as to what the flag should be `CTFlearn{a_b_c}` where a must be of length 8 so that 17th index is `_` and b must be of length 4 cuz `_` at 22nd index and last word should be 18-14 = 4 characters
so we construct flag from what we saw in strings and finally we get flag to be 
> FLAG - `CTFlearn{Princess_Maha_Devi}`
---
### 5. Ramada

we have the `Ramada` executable, first we do `chmod +x Ramada` and run `strings` on it but we find nothing and again we must be giving an argument in the form of `CTFlearn{kernel}` 
> `./Ramada CTFlearn{kernel}` 

- when we pass the argument of not correct length it says "sorry, flag length is not right" so we first need to figure out length of argument to be passed 
```c
iVar5 = strlen(puVar1);
            if (puVar1[iVar5 + -1] == 0x7d) {
                if (iVar5 == 0x1f) {
                    InitData()(arg7);
                    piVar8 = aiStack_68;
                    for (iVar5 = 0x10; iVar5 != 0; iVar5 = iVar5 + -1) {
                        *piVar8 = iVar10;
                        piVar8 = piVar8 + (uint64_t)uVar13 * -2 + 1;
                    }
                    strncpy(aiStack_68, puVar1 + 9, 0x15);
                    __printf_chk(1, "Your Flag Kernel: %s\n", aiStack_68);
                    iVar4 = CheckFlag(char const*)((int64_t)aiStack_68);
                    if (iVar4 == 0) {
```

from the line `if(iVar5 == 0x1f)` it implies that the argument must be of length 31 including CTFlearn{} , we can also figure this out by looking at assembly code in the `rax` register which is being compared to `0x1f` implying 31 character check.

in 31 chars, 10 are used by `CTFlearn{}` so the kernel part must be 21 characters long and in the above code itself we see `0x15 = 21` being copied to `aiStack_68` by `strncpy` which is then passed to the CheckFlag() function so we can infer that only kernel part is being checked by the CheckFlag() function

```c
undefined8 CheckFlag(char const*)(int64_t arg1)
{
    int64_t iVar1;
    int32_t iVar2;
    
    iVar1 = 0;
    do {
        iVar2 = (int32_t)*(char *)(arg1 + iVar1);
        if (*(int32_t *)(data + iVar1 * 4) != iVar2 * iVar2 * iVar2) {
            puts("No flag for you!");
            return 4;
        }
        iVar1 = iVar1 + 1;
    } while (iVar1 != 0x15);
    return 0;
}
```

now we need to reverse this checkflag function where data is the individual characters of the kernel which is being checked with (iVar2)^3 , we need to make that condition true so we write a script using the values from data array
```c
void InitData()(int64_t arg7)
{
    _data.00004090 = 0x1734eb;
    _data = 0x13693;
    *(undefined4 *)0x4044 = 0x6b2c0;
    *(undefined4 *)0x4048 = 0x11a9f9;
    *(undefined4 *)0x404c = 0x157000;
    _data.00004050 = 0x1cb91;
    *(undefined4 *)0x4054 = 0x1bb528;
    *(undefined4 *)0x4058 = 0x1bb528;
    *(undefined4 *)0x405c = 0xded21;
    _data.00004060 = 0x144f38;
    *(undefined4 *)0x4064 = 0xfb89d;
    *(undefined4 *)0x4068 = 0x169b48;
    *(undefined4 *)0x406c = 0xd151f;
    _data.00004070 = 0x8b98b;
    *(undefined4 *)0x4074 = 0x17d140;
    *(undefined4 *)0x4078 = 0xded21;
    *(undefined4 *)0x407c = 0x1338c0;
    _data.00004080 = 0x1338c0;
    *(undefined4 *)0x4084 = 0x11a9f9;
    *(undefined4 *)0x4088 = 0x1b000;
    *(undefined4 *)0x408c = 0x144f38;
    return;
}
```

so we write a python script to reverse these hex values and make that if condition true 
```py
import numpy as np

data = [0x13693, 0x6b2c0, 0x11a9f9, 0x157000, 0x1cb91, 0x1bb528, 0x1bb528, 0xded21, 0x144f38, 0xfb89d, 0x169b48, 0xd151f, 0x8b98b, 0x17d140, 0xded21, 0x1338c0, 0x1338c0, 0x11a9f9, 0x1b000, 0x144f38, 0x1734eb]

s = ""
for d in data:
	s+=str(hex(round(np.cbrt(int(d)))))[2:]+" "
	
print(s)
```

`output - 2b 4c 69 70 31 7a 7a 61 6e 65 72 5f 53 74 61 6c 6c 69 30 6e 73`
decoding from hex we get - `+Lip1zzaner_Stalli0ns` which is the kernel
> FLAG - `CTFlearn{+Lip1zzaner_Stalli0ns}`
---


