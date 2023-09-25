# IITBCTF QUALIFIERS

## Banarasi Paan

>Greetings, Chief Deputy Hacker of THO (The Hacker Organisation)! Your relentless pursuit of India's notorious hacker, known as "Sasta Natwarlal," has led you to a critical breakthrough. Though he managed to evade capture, you have uncovered a tantalizing clue that could  finally bring him to justice.
>
>Inside his abandoned hideout, you discovered a lone USB drive boldly labeled `"Catch me if you can."` Sasta Natwarlal's arrogance knows no bounds, but it's also his Achilles' heel. Upon connecting the drive, you find just a single text file named "Banarasi_Paan.txt." The hacker, it seems, loves a challenge.
>
> Wrap the flag in iitbCTF{...}.
>
>Flag format : iitbCTF{}
>
>Author: Jatin Singhal, Shiwani Mishra

>[Catch_Me_If_You_Can.txt](./images/Catch_Me_If_You_Can.txt)

Tags: _Miscellaneous_

## Solution

The given txt file's contents looks similar to an [`esoteric language`](https://en.wikipedia.org/wiki/Esoteric_programming_language)
called `Brainfuck cipher` which can be decoded from [`here`](https://www.dcode.fr/brainfuck-language)

![Alt text](./images/paan1.PNG)

we get a URL - `https://urlzs.com/FbD4S`

on opening the URL we see 

![Alt text](./images/paan2.PNG)

Doing `ROT13` on `XRL VF PUBE` we get output saying `KEY IS CHOR`

Now we tried using the key `CHOR` and doing `Vigenere decode` on the link given in `Brain_Damaged.rtf` but we did not get anything meaningful, we have to make some sense out of the paragraph given 

We do `vigenere decode` of the paragraph using [Cyberchef](https://gchq.github.io/CyberChef/) and given with the key `CHOR` but we still get an output like this

![Alt text](./images/paan3.PNG)

Now since there is only 2 letters `N` and `O` we can try comparing them to binary's `1` and `0` , so now using cyberchef again we can replace `N` with `0` and `O` with `1` and then convert binary to text 

![Alt text](./images/paan4.PNG)

we get coordinates in google map as `19.09817945854717, 72.82747712554809` and plug it in google maps and go to street view to find name of paan shop.

![Alt text](./images/paan5.PNG)

we can just see the name of the paan shop `MISHRA` paan shop so voila we have our key to decode the encrypted link given

on doing vigenere decode again of `tblwj://rn.oq/1cpub` using key `MISHRA` we get output as `https://rb.gy/1vyup` and on opening it we get [pcapng file](./images/PCAP_WHAT___.pcapng) which on opening with `Wireshark` and navigating through streams we can see 
```
Text 1 - hp/./o
Text 2 - ts/lSc
Text 3 - t:tyKZ
```
Now we unjumble and we already know link should start with `https://` so on putting them all together we get the link `https://t.ly/SKocZ` and on opening this we still do not have the flag we get a binary text looking file with contents 

```
1011 11111 001 001101 010 00011 01 01111 01111 1011 001101 1 00001 11111 001 110 000011 001101 1011 11111 001 001101 1010 011010 10 001101 1010 011010 1 1010 00001 00110111 00011
```

Now we tried converting from binary to text but it did not work, but then we thought of `Morse code` and replace `1` with `_` and `0` with `.` and then try decoding with cyberchef itself 

![Alt text](./images/paan6.PNG)

AND FINALLY WE HAVE OUR FLAG AFTER AN EXHILARATING CHASE OF THE NOTORIUS HACKER

FLAG - `iitbCTF{Y0U_R3A11Y_T40UG4T_Y0U_C@N_C@TC4_M3}`


