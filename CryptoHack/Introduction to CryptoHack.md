
# CryptoHack Notes

## Introduction to Cryptohack

1. **ASCII**

```
a=[99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
print("".join(chr(i) for i in a))
```
`flag : crypto{ASCII_pr1nt4bl3}`
***
2. **Hex**
```
a="63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
print(bytes.fromhex(a))
```
`b'crypto{You_will_be_working_with_hex_strings_a_lot}'`
***
3. **base64**

```
import base64
a="72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
b=bytes.fromhex(a)
print(base64.b64encode(b).decode())
```
`b'crypto/Base+64+Encoding+is+Web+Safe/'`
***

4. **Bytes and big integers**
>Cryptosystems like RSA works on numbers, but messages are made up of characters. How should we convert our messages into numbers so that mathematical operations can be applied?  

*so this is where bytes_to_long() and long_to_bytes() comes into picture*
```
from Crypto.Util.number import *
a=11515195063862318899931685488813747395775516287289682636499965282714637259206269
print(long_to_bytes(a))
```
`b'crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}'`
***
5. **XOR starter**
>Given the string `label`, XOR each character with the integer `13`. Convert these integers back to a string and submit the flag as `crypto{new_string}`.

```
a="label"
for ch in a:
    print(chr(ord(ch)^13),end="")
```
`aloha`

flag is `crypto{aloha}`
***
6. **XOR properties**

>Commutative: A ⊕ B = B ⊕ A  
  Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C  
  Identity: A ⊕ 0 = A  
  Self-Inverse: A ⊕ A = 0

>given details :
>KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313  
  KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e  
  KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1  
  FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf

```
def xor_two_strings(s1,s2):
    result = ''.join(format(int(a,16)^int(b,16), 'x') for a,b in zip(s1,s2))
    return result
    
k1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
k2_k1 = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
k2_k3 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
flag_k1_k3_k2 = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

k2 = xor_two_strings(k1,k2_k1)
print("key2 =",k2)

k3 = xor_two_strings(k2,k2_k3)
print("key3 =",k3)

k1_k2_k3 = xor_two_strings(k1,k2_k3)

flag = xor_two_strings(flag_k1_k3_k2,k1_k2_k3)
print("flag :",bytes.fromhex(flag))
```
`flag : b'crypto{x0r_i5_ass0c1at1v3}'`

- zip(a,b) basically joins two tuples, lists etc element wise into a single tuple 
	>if a=[1,2,3] and b=['x','y','z'] 
	>then zip(a,b) returns [(1, 'x'), (2, 'y'), (3, 'z')]
	
- int(a,16) basically says 'a' is base16 (hex) and convert that to decimal
- format(arg1, 'x') basically says to convert the decimal integer value arg1 into string representation in hexadecimal notation
---
7. **Favourite Byte**
	>I've hidden some data using XOR with a single byte, but that byte is a secret. Don't forget to decode from hex first.
	
	first thing that comes to mind is bruteforce with all possible hex bytes (0-255)

 ```
 a=bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

for i in range(256):
    res = [chr(ch ^ i) for ch in a]
    flag="".join(res)
    if "crypto" in flag:
        print(flag)
        print(i-1)
```
`flag : crypto{0x10_15_my_f4v0ur173_by7e}`
***

8. **You either know, XOR you don't**
> I've encrypted the flag with my secret key, you'll never be able to guess it.
>`0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104`

- so the flag is encrypted with a secret key to get the hexadecimal string but we know `XOR` is associative property and we expect flag's initial part to be according to flag format `crypto{`
- we XOR the bytes of hex string with `crypto{` and try to reveal the secret key, basically reverse XOR and then with the key, `match it to 'a' length` by repetition of key  and do XOR and get the flag

```
a=bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")
b="crypto{"

res=[chr(ch1 ^ ord(ch2)) for ch1,ch2 in zip(a,b)]
print("".join(res))

c="myXORkey" # obtained from 'res'

key=c*(len(a)//len(c)+1) # matching length of 'a'
print(key)

flag=[chr(c1 ^ ord(c2)) for c1,c2 in zip(a,key)]
print("".join(flag))
```

```
myXORke
myXORkeymyXORkeymyXORkeymyXORkeymyXORkeymyXORkey
crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}
```
---