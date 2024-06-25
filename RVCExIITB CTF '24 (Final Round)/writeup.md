
### _1. HoaX Decode_
##### _Category - Forensics_
> Author - Bipin Raj

We're given a `7z` file which contains `snack.jpg` and a text file both indicating to look at the bytes and from the challenge name as well, it hints at HxD editor, so we open it up in HxD to look for some clues <br>

![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/2c6b0353-c1e0-4799-9841-c96a1cb02954)
<br>
We can see these sus files in the bytes along with `PK` at the end and `PK` usually indicates `zip files` , so we do `ctrl+F` and search for zip file magic header - `50 4B 03` <br>

![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/d9a52b48-22ea-4dac-a114-a9da0d3ea10c)

Now we extract all the bytes after the highlighted `PK` and create a new file and save it with `.zip` extension <br> 

![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/382a6a07-5e48-4fe9-9add-4acd13a94143)
 <br> 

on opening the zip file, we get a `lorem.docx` and `readme.txt` file which has some false positive whitespaces in it along with a description indicating we have to either fix the file or is it even fixable. 
We try opening lorem.docx but it seems to be corrupted, doing some research, you can find out that .docx files are actually just .zip files consisting of various elements like `xml entities` and so on, so we rename it to lorem.zip <br>
We don't try fixing the file, instead we look for some sus stuff inside the structure of the file and we find :
`<!-- treatfortheyes:katb.in/macerokahes -->` in `styles.xml` <br>

In that link we get a huge base64 string, trying to decode that 
[cyberchef recipe](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Render_Image('Raw')) , we get an image saying `flaggity flag down here` is down here <br> 
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/afa1c2da-7d71-4372-8f62-3c7c50af1f0a)

refer this [article](https://cyberhacktics.com/hiding-information-by-changing-an-images-height/) to learn how to increase the dimensons of the image and view the remaining part of the image.
`FF C0 00 11 08 01` --> `FF C0 00 11 05 02` gives us : <br>
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/46851e66-d9a9-4a2e-8ffe-8a386b6351bb) <br>
now change it to `FF C0 00 11 05 03` and we can see the flag <br>
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/70f7f99d-8eba-43bd-a9da-78d1964f532f)

> FLAG - **flag{we_g0t_iM4g3s_b64_bef0re_gTa6??}**
---

### _2. The Subconscious Mind_
##### _Category - Forensics_
> Author - Bipin Raj

Right off the bat, we can see the image and bottom right is kinda corrupted so definitely something to do with the bytes. <br>
looking at metadata, we can see base64 string `c2VjcmV0IGtleSAtIG5vbGFuJ3MgYmlydGhwbGFjZQ==` which converts to `secret key - nolan's birthplace` which is `Westminster` in london. <br>
Now opening it up in hex editor :
It starts with `FF D8` indicating that it's a `jpg` image, you can read more about image headers - [here](https://www.garykessler.net/library/file_sigs.html) , now we search for trailer of `jpg` which is `FF D9` <br>
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/62e03c27-8d2f-4bb0-b10c-84e00ea342c7) <br>
right after trailer bytes, we can see corrupted `png` bytes starting with magic header `89 50 4E 47` and so on, so extract these bytes and correct that critical chunks like `IHDR, IEND, IDAT` etc  <br>
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/6f4e1b30-57bb-4791-91bb-66ec344057d7) <br>
then rename it to `.png` file extension and then open it up, we get an image of a totem with the ciphertext <br>
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/045f0292-274b-47ed-b553-1666d685fb9a) <br>

now we have secret key - `westminster` so vigenere decode it and we get the flag <br> 

> FLAG - **rvcectf{christ0ph3rnol4n_gen1u5}**
---

### _3. ODio_
##### _Category - Forensics_
> Author - Bipin Raj

Idk why there was just 1 solve on this, it was pretty straightforward with the hints being released with 1h remaining for the ctf.
Hints released:
```
- waav me likey steg
- hex me text me
```

The entire challenge can be summed up in the last line tbh
> `L's Secrets Buried Deep within.` - indicating `LSB` and deep within indicating `deepsound` which is a famous stego tool.

In order to extract the hidden files from deepsound, we need a password and for the password we need a password hash to decrypt and crack. <br>
![[Pasted image 20240623234957.png]]
so with the password `shinigamiryuk`, we extract the hidden files <br>
![[Pasted image 20240623235125.png]]
we get 3 secret audio files and we will do more audio recon on them
- `secret1.wav` sounds like a phone number being typed and that indicates `DTMF tones`, so use [DTMF decoder](https://dtmf.netlify.app/) to decode to decimal, we get 
> `Decoded: 2306925064908087525729748307260966546393425247`
 
 then convert it to hex and further convert hex to ascii text using [rapidtables converter](https://www.rapidtables.com/convert/number/decimal-to-hex.html) , we get 1 part of the flag as `gr3t4e5t_det3ct1ve_`

  - `secret2.wav` was to be opened up in `audacity` or `Sonic Visualizer` to look at it's `spectogram` to get another part of the flag
![[Pasted image 20240624001159.png]]
another part of flag - `0n_Pl4net_3arth}`

- `secret3.wav` is LSB encoded and we can try different tools like stegolsb, wavsteg and so on and seeing the hint it is definitely `wavsteg` <br>
 just type wavsteg download and 2nd link that appears on google is the github repo to clone and use - [wavsteg repo](https://github.com/pavanchhatpar/wav-steg-py)  
 along with the 3 secret audio files there was a `hint.txt` attached too which said `secret3 hidden in 2 channels with 18bytes` 
 so using all this info, we can recover data by: 
 
```
┌──(kali㉿kali)-[~/Downloads/wav-steg-py]
└─$ python wav-steg.py -r -s ../secret3.wav -o flag.txt -n 2 -b 18
Data recovered to flag.txt text file
                                                                
┌──(kali㉿kali)-[~/Downloads/wav-steg-py]
└─$ cat flag.txt  
flag{L4wl1et_th3_
```
And just like that we have all the 3 parts. <br>
> FLAG - **flag{L4wl1et_th3_gr3t4e5t_det3ct1ve_0n_Pl4net_3arth}**
---

### _4. RAW_
##### _Category - Miscellaneous_
> Author - Bipin Raj

We're given a pretty big zip file which is apparently a `data dump` and it contains a lot of subfolders and subfiles, so what's the first thing that comes to mind?
If your answer was `grep with flag format` - you're right!
`grep -arni "flag"` - but it gives us a fake flag (as it says red herring)
>- Search recursively (`-r`) through all files and directories.
>- Treat binary files as text (`-a`).
>- Print the line numbers (`-n`) along with the matching lines.
>- Perform a case-insensitive search (`-i`) for the pattern "flag".

`grep -arni "=="` --> this gives us a `base64` string which on decoding leads us to a [drive link](https://drive.google.com/drive/folders/1y3iPURcozDEnWwmFDaOlBTUUNv5YS_u-) 
it contains a `jpg image` and `info doc` which had a `hidden key` which could be visible by simply doing `ctrl+A` 
`KEY - keyishidd3n` 
Now we perform recon on the image with exiftool, strings, binwalk and so on..
exiftool reveals `It's here somewhere, find it.` but in base64
since we have a key, let's try `steghide` 
`steghide --extract -sf transmission.jpg` with password as `keyishidd3n` and it gives us `secret.txt` whose content is 
`/d/1hK3tV5PPtdOwUujHOqQOgl1NI015GpNU/` - this looks awfully similar to URL endpoint of drive links so we construct the URL as 
```
https://drive.google.com/file/d/1hK3tV5PPtdOwUujHOqQOgl1NI015GpNU/
```
Now we get a locked zip file, in order to unlock it - we use `john the ripper`
> `zip2john agentnotebook.zip > hash`
> `john hash` - this cracks the hash and gives us the password as `topgun`

Now on extracting the _important.txt_ , the word `HISTORY` is in caps and the `.git` folder should have been a giveaway pointing towards looking at the `git commit history`
> `git log` - this shows all the commits with its hash, author name, timestamp
> `git reflog` - brief of the above, only what's needed, the hash
> `git show f0c2f2e91db329896a643b70ef43e2803849b2cd` - hash of commit3
> `git show dd427cea5c4a24ad28d352a1391b7a7cfcf457ec` - hash of commit4
> `git show 4fda7dec868ba8a29700a30bac03b90ede27be9b` - hash of commit5
>
>we get the flag in 3 parts in the commits 3,4 and 5
>FLAG - **flag{th3_j0urn3y_t0_b3_a_R4W_ageNt_i5_n0T_aN_ea5Y_on3}**
---

### _5. Crack the Vault_

##### _Category - Miscellaneous
>Author - Bipin Raj

We are given an encrypted file which is a `mountable disk` and `Veracrypt` is mentioned, it is a free open-source utility for on-the-fly encryption (mainly for disks and partitions) and partial password is given as well - `shady****1`
Running `strings` doesnt give anything, we have got to decrypt it but where's the hash? 
[finding hash of veracrypt encrypted volumes](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_do_i_extract_the_hashes_from_truecrypt_volumes) - this tells us how we can obtain the hash of the encrypted disk
In this case we have just a file, a non-booting partition so we choose option 3 
`3.in all other cases (files, non-booting partitions) you need the first 512 Bytes of the file or partition.`

So using `dd` (The `dd` command in Linux is **a robust tool that can be used to copy and convert files**) we can extract the first 512 bytes and of the encrypted file and use it as the hash
```
dd if=encrypted of=encrypted_hash bs=512 count=1
``` 
this command creates a file `encrypted_hash` with bs=512 (indicating bytesize) , count=1 (indicating it should be copied as 1 block of data)
Now that we have the hash, we turn to the advanced password cracking tool - [hashcat](https://hashcat.net/hashcat/) , on the [hash example page](https://hashcat.net/wiki/doku.php?id=example_hashes)  we can see the different kinds of hashes that hashcat can decrypt and we find `13722 - VeraCrypt PBKDF2-HMAC-SHA512 + AES-Twofish (legacy)` 
```
──(bipinraj㉿kali)-[~/Downloads]
└─$ hashcat -a 3 -w 1 -m 13722 encrypted_hash shady?d?d?d?d1

encrypted_hash:shady23781                                 
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13722 (VeraCrypt SHA512 + XTS 1024 bit (legacy))
Hash.Target......: encrypted_hash
Time.Started.....: Tue May 14 00:46:42 2024 (36 secs)
Time.Estimated...: Tue May 14 00:47:18 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: shady?d?d?d?d1 [10]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       22 H/s (1.14ms) @ Accel:256 Loops:125 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```
Breaking down the command :
> `-a 3` = attack-mode set to 3 which is bruteforce attack <br>
> `-w 1` = workload profile to normal level <br>
> `-m 13722` = hash type to be cracked <br>
> `encrypted_hash` = hash to be cracked <br>
> `shady?d?d?d?d1` = mask/pattern for bruteforce attack `?d` bruteforces with a digit from `0-9` but keeps `shady` and `1` in the beginning and end intact <br>
> _password obtained = shady23781_

Now we can use the [Veracrypt utility](https://sourceforge.net/projects/veracrypt/) to decrypt and mount the encrypted disk using the above password, on a successful mount, on opening the drive we get a `flag.txt` :
```
was this your progressive mental state while trying to solve this ?
😆🤯😳😏😀😕😞😛😞😙😥😑😚🤠😇🤮🤪😒😡🤔😶😄😵😔😶😆😰😰😜😟😲🤭🤢😨😐😨🤨🥱😦😒😡😴🥰😜🤫😖🤩🤔🤢🤓😖😇😔😳😂😵😁😐😯😅😳😞😞🥱😥🤡🤬😯😑😷😦😇😕😳😚😵😋😋
emojis
```
We can use [Cryptoji decoder](https://cryptoji.com/) with password as `emojis` and obtain the flag 
> FLAG - **flag{3ncrypt3d_d15k_n0t_s0_53cUre_huh?}**
---
### _6. The Forgotten Binary_

##### _Catgeory - Stego_
> Author - Bipin Raj

Im sure a lot of you probably want to see this writeup, hope this enlightens you on this method of steganography ;)
So, we have a binary file `rm` given to us and now first things first
Running `strings` on the binary doesn't give anything solid, so we try to run it 
`chmod +x rm`
`./rm` - this binary works exactly like the linux command `rm` 
in fact let's compare them :
```py
┌──(bipinraj㉿kali)-[~/Desktop/CTF_Tools/steg86]
└─$ file rm     
rm: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e8b7e344eda821652030f20cd66139fba719927b, for GNU/Linux 3.2.0, stripped

┌──(bipinraj㉿kali)-[~/Desktop/CTF_Tools/steg86]
└─$ file /bin/rm
/bin/rm: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e8b7e344eda821652030f20cd66139fba719927b, for GNU/Linux 3.2.0, stripped
```
looks the same (even the checksum)
let's compare the bytes by `diff <(hexdump -C /bin/rm) <(hexdump -C ./rm)`

![[steg86.png]] 
It looks like some kind of steganography, because some bytes![[steg86.png]]
are changed, just like LSB steganography in images. But is there steganography for binaries?
[steg86](https://github.com/woodruffw/steg86): _steg86 is a format-agnostic steganographic tool for x86 and AMD64 binaries._ 
more about the working of it - [here](https://github.com/woodruffw/steg86?tab=readme-ov-file#theory-of-operation) 
`./steg86 extract rm > flag.txt`
>FLAG - **rvcectf{1n5piR3d_bY_R1SV_b1n4ri3s_5te5aN0gr4pHy}**
---
### _7. Scroll of Destiny_
##### _Category - OSINT_
> Author - Bipin Raj

On doing reverse image search, we can conclude the image is related to  [Gallifreyan language](https://tardis.fandom.com/wiki/Gallifreyan_(language)) (mystic language of the Time Lords) , now we need to decode this and for that we need to know the rules of Circular Gallifreyan so by searching around we can find - [ultimate guide to gallifreyan](https://translationmatrix.tumblr.com/post/179867130691/the-ultimate-guide-to-circular-gallifreyan-in-all) and can do trial and error with the [gallifreyan decoder](https://adrian17.github.io/Gallifreyan/) and finally :

![[gallifreyan1.png]] 
_Note : The circular patterns match up exactly and the lines arrangement do not matter. Sherman's Gallifreyan isn't a 1 to 1 translation to & from English, it's a one to many from english to Gallifreyan, a bit like how there are an infinite number of fonts for english, but you can still read them all the same_ 

Now we look up `@skibidiboo` on instagram and find a post with a `pastebin` link and a question asking "Which ancient book does Dr Strange read for astral projection" - `vishanti`

This leads to a drive link with an image of a temple 
![[gallifreyan2.png]]

Seeing exact match - it leads us to [this website](https://www.walksworldwide.com/blog/filming-locations-doctor-strange-in-nepal) and now we know the name of the temple `swayambhunath` and with a simple google search of how many steps it takes to get from the main gate to the stupa of the temple, it says `365` 
 
> FLAG - **flag{swayambhunath_365}**
---
### _8. Geoguessr Lite_
##### _Category - OSINT_
>Author - Bipin Raj

>Gaurav visited a place and posted it on X and it resonated so much with him that he joined there and works there, find out more about it and you shall find what you seek.  
  PS: communication is key.

First thing that comes to mind is `Geosint`, starting off with our OG google reverse image search with google lens <br>
![[reverse-image-search.png]]
keep adjusting the croppable part in such a way that you find Gaurav's X post
https://twitter.com/gaurav_goyal27/status/474076303964909569

![[Pasted image 20240625005658.png]]
pastebin link - https://pastebin.com/xH8yhhGf <br>
>Key takeaways from the tweet and description
>- going to visit same place `NEXT YEAR same time` with friend kate
>- mail `bipinrajc4604@gmail.com` for more info
>- desc said communication is key so def something to do with sending a mail

so when we do send a mail to `bipinrajc4604@gmail.com`, you get an automatic reply with an _**ImPoRtANt**_ mail with the link - https://rb.gy/jaqonj which ofc had to be a rickroll lol

pastebin link says 
```
my friend kate sent me this, cant make out what it is, maybe ask her what it is.
https://drive.google.com/file/d/1mTf_2Lo3hNK-IlpbsY1bGA8YHmkul4bz/view?usp=sharing
```
maybe ask kate what it is? since it said kate sent me this, look at image metadata but unexpectedly author comment is `bipinrajc4604@gmail.com` , but we need kate's mail and send her a mail.<br>
The reason author isnt kate but is `bipinrajc4604@gmail.com` you had to find out kate's mail merely by knowing my mail and how's that? That was the trick/main task of this challenge. <br>
From key takeaways we know he will visit art of living again _**same time next year**_, so maybe we can look at his calendar and leak some private info if he hasn't properly set up google calendar like most people.
Here's everything to read on how to do the next step - [google calendar OSINT](https://logicbomb.medium.com/ok-google-please-reveal-everyones-public-calendar-27523206f9ac) 
```
google dork (advance search query) to use:
https://calendar.google.com/calendar?cid=bipinrajc4604@gmail.com
```

![[Pasted image 20240625011510.png]]
go to `June 22, 2025` and we can see guest as `katelynsera@gmail.com` 

> Only after hint was given people were able to figure out this much
> Hints :
>- Gaurav posted a photo on X and he's just new to X with no followers 
>- have i scheduled a public event with kate?

For some reason many of yall kept finding different Gauravs and not the right one hence the above hint and the 2nd hint was direct giveaway. <br>
So now mail `katelynsera@gmail.com` and we'd get a mail in reply :
![[Pasted image 20240625012047.png]]

> FLAG - **flag{0h_ye4h_y0u_f1nally_got_me}**
---

### _9. MOV or Coldplay?_
##### _Category - Stego_
> Author - Bipin Raj

We're given a `chall.txt` which has some weird whitespaces appended at the end of the text file and looking at that, whitespace steganography strikes and the tool is [stegsnow](https://wiki.bi0s.in/steganography/stegsnow/) , but we need a password and it can be found within the text file itself - `secret code phrase - operaoctopus` <br>
```
┌──(kali㉿kali)-[~/Downloads]
└─$ stegsnow -C -p "operaoctopus" chall.txt decoded.txt
                                         
┌──(kali㉿kali)-[~/Downloads]
└─$ cat decoded.txt 
Now, that you're past the first layer, you're gonna find a mysterious and weird hidden text file, make of it what you will https://cybersharing.net/s/6945fb8e0e93bdb6
```

Now opening up the `cybersharing` link, we get `hidden.txt`
```
Dylan says pursuit of adrenaline must be never-ending
shout (at) Dylan
Phil says but that's the fun
say (yes) Phil 
bobby says C
(for)crime is continuous
universe is resplendent
shout bobby 
say crime (shouldn't be)
(but) whisper universe (is beautiful)
dobby says d
say dobby
peter says p
whisper peter
(but) whisper universe (is beautiful)
life is hard
say life (is what? is hard)
georgia says Y
say georgia(it's just like that)
nature says R
whisper nature 
beauty is wilderness
whisper beauty
bobby (again) says C
(so just) shout bobby
(we're such insignificant beings in this beautiful universe, just live it bobby)
secret says k
whisper secret
(finally) the truth is great
whisper the truth
```
Indeed is weird and whenever you see weird you think `esoteric language` and start looking for hints in the description and challenge overall.
> - Coldplay is a `rock genre` band and `cold` somewhat indicates `stegsnow` 
> - `Dylan` Beattie is creator of `Rockstar` programming language

use this compiler - [Rockstar Programming Language](https://codewithrockstar.com/online)
![[Pasted image 20240625015341.png]]

> FLAG - **flag{C01dp14YR0Ck5}**
---

### _10. Cryptomaze_
##### _Category - Crypto_
> Author - Bipin Raj

okay, so this challenge troubled so many of you, honestly i have no clue why, everything was in the descriptions, plainly copy and paste in google and it'd give u leads.
People probably didn't read the text and when they see a link, they just directly open it and are stuck clueless there.
Especially when last 1h was left the hints were spoonfed <br>
```
Hints
- Frequency analysis with high efficiency
- descriptions lead to further katbin links
- perpetually gray town, was he a sad nihilist?
- CITRIX CTX ?
```
First we have `chall.txt` <br>
```
ie nkesa kyifciati'd "niwiea pxvanl," sca aifcsc pitpya xz cayy id nadifeksan zxt ztkrndsatd ken id drjniwinan iesx sae nispcad, akpc ureidcief k nizzataes slua xz napais. oiscie scid pitpya, dieeatd drzzat wktixrd sxtvaesd, drpc kd jaief drjvatfan ie jxiyief uispc xt jaief ociuuan jl navxed, tazyapsief sca pxttrus ken napaiszry eksrta xz scait died.cssud://hksj.ie/amibajatxyx
```
It looks like some alphabetic substitution, many of them did monoalphabetic substitution on `dcode.fr` and got the words right but link wrong, cuz link has got more `entropy` than words and whilst `dcode.fr` does a good job with words, it wouldn't get the link right.  <br>
Enter the legendary frequency analysis tool - [Quipqiup](https://www.quipqiup.com/)
<br>![[Pasted image 20240625021447.png]]
By simple google search, the decoded description points towards `malbolge` language which is named after 8th circle of hell in Dante's Inferno <br>
so paste the contents of `https://katb.in/exijeberolo` in [Malbolge Interpreter](https://malbolge.doleczek.pl/)<br>
On decoding it gives:
```
In a perpetually gray town called citrixia, Elias led a monotonous, purposeless life. One day, he discovered an old book about finding meaning in unexpected places. Inspired, he began painting and connecting with others, gradually bringing color and warmth into his life. Though the skies stayed overcast, Elias created his own sense of purpose through small acts of creation and connection.
what is Elias?
https://katb.in/urelegoyaxu
```
What is Elias? He's a Nihilist - now use [Nihilist cipher decoder](https://cryptii.com/pipes/nihilist-cipher) to decode the contents of 2nd katbin link with key as `citrixia` which is the name of the city 
> Because it said, **the key to it all is the name of the city**

![[Pasted image 20240625022246.png]]
construct the next katbin link - `https://katb.in/ugoqikumaxe` 
and now decode that using [CITRIX CTX 1 cipher decoder](https://asecuritysite.com/cipher/citrix)  <br>
![[Pasted image 20240626010934.png]]

> FLAG - **flag{3ncrypted_c0mm5_fr0m_a_5ecure_w0rld}**
---

### _11. Quantum - Classic Bridge_
##### _Category - Crypto_
> Author - Bipin Raj

So from the description, it seems like there is some kind of communication taking place between a `classical computer` and a `quantum computer`. We're given a transmission : <br>
```
Genesis state: 1/sqrt(2)*(|00> + |11>)

message:
X X I I X Z ZX ZX X ZX I ZX X ZX X I I Z I I X X I X X ZX X X X Z I X X Z ZX Z X ZX X I X ZX X X X Z ZX X I Z I I X I I ZX X ZX I Z X ZX Z X X ZX I I X ZX X I X Z ZX ZX X Z X ZX X ZX I Z X Z I X X ZX I I X Z Z I X ZX Z X I Z I I X Z Z X X ZX I ZX I Z I I X ZX X I X Z Z I X Z X X I Z I I X Z X Z X ZX X X X ZX X I X ZX X X X ZX I Z X Z X X I Z I I X Z ZX ZX X Z X Z I Z I I X X I ZX X Z X X X Z I ZX X ZX X X X ZX I Z X Z X X I Z I I X Z I X X ZX I I X ZX I I X Z ZX I X Z Z X X Z I ZX X Z I X X ZX X I X Z Z X X Z ZX ZX X Z ZX Z X ZX I ZX I Z I I X Z X Z X Z ZX I X Z I X X Z X ZX X ZX Z ZX X Z X Z X ZX X X X X X I X ZX X X X ZX I Z I ZX I ZX X X ZX ZX I ZX I I X Z X Z X X ZX ZX X Z I ZX X ZX I Z X ZX Z X X ZX I I X ZX X I I ZX I I X Z X ZX X ZX I Z I ZX X I X ZX I I X Z Z I X X Z X X X ZX ZX I ZX I X X ZX I ZX X X ZX ZX I ZX X X X Z X X X Z I ZX X X X X X ZX I Z I ZX I ZX X ZX ZX X
```

So how do we get started, looking at `X Z I` string can be intimidating, but let's approach this easily, first off google is your friend so search it up in google but it gives some weird stuff so then go for chatgpt (dont even have to tell you lol) <br>
![[Screenshot 2024-06-26 012521.png]]
So now we know that it's something to do with the `Quantum gates` and X indicates Pauli-X gate , Z is Pauli-Z gate , I is identity gate and so on. <br>
Many of you must've come across this writeup on ctftime as well - [X-MAS CTF 2019](https://ctftime.org/writeup/17535) and there is a given decryption script there, except when u try to use that, it doesnt work, because it's slightly different from how I had encoded it. <br>
So if you could understand the difference then it could be solved easily, difference was the way it had been encoded and decrypted in the writeup using the `genesis state` and going forward to next states in the iteration for the entire string. <br> 
But here, what had to be done was instead of using genesis state and going to further successive states, just reset the `init1` and `init2` variables _**inside**_ the loop and now for every single iteration it resets and decrypts correctly. So actually the genesis state doesn't even have to be used. It was still given though cuz there are probably other ways to decrypt using genesis state but a different slightly complex logic.

Here's my decryption script, but playing around with chatGPT with the right prompts after understanding what it revolves around could probably give you another solution. <br>
```py
import numpy
import binascii

message = "X X I I X Z ZX ZX X ZX I ZX X ZX X I I Z I I X X I X X ZX X X X Z I X X Z ZX Z X ZX X I X ZX X X X Z ZX X I Z I I X I I ZX X ZX I Z X ZX Z X X ZX I I X ZX X I X Z ZX ZX X Z X ZX X ZX I Z X Z I X X ZX I I X Z Z I X ZX Z X I Z I I X Z Z X X ZX I ZX I Z I I X ZX X I X Z Z I X Z X X I Z I I X Z X Z X ZX X X X ZX X I X ZX X X X ZX I Z X Z X X I Z I I X Z ZX ZX X Z X Z I Z I I X X I ZX X Z X X X Z I ZX X ZX X X X ZX I Z X Z X X I Z I I X Z I X X ZX I I X ZX I I X Z ZX I X Z Z X X Z I ZX X Z I X X ZX X I X Z Z X X Z ZX ZX X Z ZX Z X ZX I ZX I Z I I X Z X Z X Z ZX I X Z I X X Z X ZX X ZX Z ZX X Z X Z X ZX X X X X X I X ZX X X X ZX I Z I ZX I ZX X X ZX ZX I ZX I I X Z X Z X X ZX ZX X Z I ZX X ZX I Z X ZX Z X X ZX I I X ZX X I I ZX I I X Z X ZX X ZX I Z I ZX X I X ZX I I X Z Z I X X Z X X X ZX ZX I ZX I X X ZX I ZX X X ZX ZX I ZX X X X Z X X X Z I ZX X X X X X ZX I Z I ZX I ZX X ZX ZX X"

messageDigest = message.split(" ")

X = numpy.array([[0, 1], [1, 0]])
I = numpy.array([[1, 0], [0, 1]])
Z = numpy.array([[1, 0], [0, -1]])
ZX = numpy.dot(Z, X)
H =  numpy.array([[1, 1], [1, -1]])
CNOT = numpy.array([

    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 0, 1],
    [0, 0, 1, 0]
])

XI = numpy.kron(X, I)
II = numpy.kron(I, I)
ZI = numpy.kron(Z, I)
ZXI = numpy.kron(ZX, I)
HI = numpy.kron(H, I)

digest = ""

for m in messageDigest:
    init1 = numpy.array([1, 0, 0, 0])
    init2 = numpy.array([0, 0, 0, 1])

    if m == "I":
        init1 = numpy.transpose(numpy.dot(init1,II))
        init2 = numpy.transpose(numpy.dot(init2,II))

    elif m == "X":
        init1 = numpy.transpose(numpy.dot(init1,XI))
        init2 = numpy.transpose(numpy.dot(init2,XI))
    
    elif m == "Z":
        init1 = numpy.transpose(numpy.dot(init1,ZI))
        init2 = numpy.transpose(numpy.dot(init2,ZI))
    
    elif m == "ZX":
        init1 = numpy.transpose(numpy.dot(init1,ZXI))
        init2 = numpy.transpose(numpy.dot(init2,ZXI))
    
    else:
        print("Unknown Op: {0}".format(m))

    dig1 = numpy.transpose(numpy.dot( init1,CNOT))
    dig2 = numpy.transpose(numpy.dot(init2, CNOT))
    dig1 = numpy.transpose(numpy.dot(dig1,HI))
    dig2 = numpy.transpose(numpy.dot(dig2,HI))
    dig = dig1 + dig2
    if dig[0] != 0:
        digest += "00"
    elif dig[1] != 0:
        digest += "01"
    elif dig[2] != 0:
        digest += "10"
    elif dig[3] != 0:
        digest += "11"
n = int('0b'+digest,2)
print(n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore'))
```
<br>
Im too lazy to type an explanation of code so here's a snippet from chatgpt :
![[Pasted image 20240626015023.png]]

```
Output:
Post Quantum Cryptography is the future of Secure applications flag{fuTur3_0f_crypt0gr4phY_1s_5ecUr3}
```
The main theme this revolves around is `Superdense coding` which is a quantum communication protocol - read up more on this from [Superdense coding](https://medium.com/geekculture/understanding-superdense-coding-c10b42adecca) 

> FLAG - **flag{fuTur3_0f_crypt0gr4phY_1s_5ecUr3}**
---




