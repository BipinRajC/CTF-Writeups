---
description: Category - Easy
---

# Cryptography \[Easy]

## 1. **Base 2 2 the 6**

encoded text is given: Q1RGe0ZsYWdneVdhZ2d5UmFnZ3l9

throw it in cyberchef with 'from Base64' as recipe

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

We get the flag:

FLAG: _**CTF{FlaggyWaggyRaggy}**_

***

## 2. BruXOR

encoded text: q{vpln'bH\_varHuebcrqxetrHOXEj

throw it in cyberchef and put XOR Brute Force as recipe and we get the flag at key = 17

<figure><img src=".gitbook/assets/BruXOR.png" alt=""><figcaption></figcaption></figure>

FLAG: _**flag{y0u\_Have\_bruteforce\_XOR}**_

***

## 3. Character Encoding

Encoded text is given: 41 42 43 54 46 7B 34 35 43 31 31 5F 31 35 5F 55 35 33 46 55 4C 7D

convert it to get the flag, it looks like hex values so throw it in cyberchef and put magic as recipe or put 'From hex'

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

we get the flag

FLAG: _**ABCTF{45C11\_15\_U53FUL}**_

***

## 4. Hextraordinary&#x20;

From challenge description, we get a hint that there is something to do with XORing

chall description: Meet ROXy, a coder obsessed with being exclusively the worlds best hacker. She specializes in short cryptic hard to decipher secret codes. The below hex values for example, she did something with them to generate a secret code, can you figure out what? Your answer should start with 0x.

0xc4115 0x4cf8

Now put both these values in a XOR calculator - [https://xor.pw/#](https://xor.pw)

OR (use python)

print(hex(0xc4115^0x4cf8))&#x20;

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

We get "c0ded"

FLAG: _**CTFlearn{0xc0ded}**_

***

## 5. HyperStream Test #2&#x20;

from the challenge description, we can infer that Bacon Cipher is used!

encoded: ABAAAABABAABBABBAABBAABAAAAAABAAAAAAAABAABBABABBAAAAABBABBABABBAABAABABABBAABBABBAABB

put it in - [https://www.dcode.fr/bacon-cipher](https://www.dcode.fr/bacon-cipher)

<figure><img src=".gitbook/assets/Hypertest stream #2.png" alt=""><figcaption></figcaption></figure>

FLAG: CTFlearn{ILOUEBACONDONTYOU}

***

## 6. Modern Gaius Julius Caesar

it is just another substitution cipher and given encoded text: **BUH'tdy,|Bim5y\~Bdt76yQ**

real hint: "Why should you when you have your keyboard?" meaning keyboard shift cipher

we use the website for decoding: [https://www.dcode.fr/keyboard-shift-cipher](https://www.dcode.fr/keyboard-shift-cipher)

<figure><img src=".gitbook/assets/modern day julius.png" alt=""><figcaption></figcaption></figure>

we get CTFlearn{Cyb3rCae54r} but put an underscore in between and then submit the flag

FLAG: _**CTFlearn{Cyb3r\_Cae54r}**_

***

## 7. Morse Code

Morse coded text is given:

..-. .-.. .- --. ... .- -- ..- . .-.. -- --- .-. ... . .. ... -.-. --- --- .-.. -... -.-- - .... . .-- .- -.-- .. .-.. .. -.- . -.-. .... . . ...

throw it in cyberchef and put 'From Morse' as recipe, we get the flag

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

FLAG: _**FLAGSAMUELMORSEISCOOLBYTHEWAYILIKECHEES**_

in morse code "{}" is not shown usually so add this according to the format of the flag and submit (in this case {} not required)

***

## 8. Reverse Polarity

encoded text is given in binary format:

01000011010101000100011001111011010000100110100101110100010111110100011001101100011010010111000001110000011010010110111001111101

throw it in cyberchef and put recipe as 'From Binary', we get the flag

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

FLAG: _**CTF{Bit\_Flippin}**_

***

## 9. Suspecious Message

a photo is attached which is translation grid which is basically parameter for decoding from playfair cipher

{% file src=".gitbook/assets/photo.png" %}

encoded text: MQDzqdor{Ix4Oa41W\_1F\_B00h\_m1YlqPpPP}

Playfair cipher - identify from challenge description as it says name of person who sent it is FARI which kinda indicates fair

use website: [https://www.boxentriq.com/code-breaking/playfair-cipher](https://www.boxentriq.com/code-breaking/playfair-cipher)

![](<.gitbook/assets/image (5).png>)  ![](<.gitbook/assets/image (6).png>)

enter the cipher and set the translation grid accordingly - QWERTYUIOPASDFGHKLZXCVBNM (5x5 grid)

FLAG: _**CTFLEARN{PL4YF41R\_1S\_C00L\_C1PHERRRR}**_

***

## 10. Tone Dialing

.wav file is given, upload it onto a DTMF(Dual Tone Multi Frequency) decoder

{% file src=".gitbook/assets/you_know_what_to_do.wav" %}

website: [https://dtmf.netlify.app/](https://dtmf.netlify.app/)

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

we get the decoded decimal value: 67847010810197110123678289808479718265807289125

now convert this base10 value to ASCII

listen to the audio and fragment the decoded decimal value, 2 beeps=2 numbers grouped and 3 beeps=3 numbers grouped

after fragmentation: 67 84 70 108 101 97 110 123 67 82 89 80 84 79 71 82 65 80 72 89 125

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

or just upload as it is on this link: [https://onlinetools.com/ascii/convert-decimal-to-ascii](https://onlinetools.com/ascii/convert-decimal-to-ascii)

FLAG: _**CTFlean{CRYPTOGRAPHY}**_

***

## 11. Vigenere Cipher

In the challenge description, clearly theres a key given "blorpy"

and also encoded text- gwox{RgqssihYspOntqpxs}

throw it in cyberchef and put Vigenere cipher as recipe and put 'blorpy' as key and we get the flag

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

FLAG: _**flag{CiphersAreAwesome}**_
