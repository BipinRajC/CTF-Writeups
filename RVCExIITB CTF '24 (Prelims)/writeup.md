
### _1. Secrets From The Past_
##### _Category - Crypto_
There is a `configuration.txt` file given and from the description with some googling, it sounds like it was some kind of a physical machine used in WW2 for secret communication - `Enigma Machine`
```
Enigma M3

UKW B

VI	1A	2B
I	3C	4D
III	5E	7G

bq cr di ej kw mt os px uz gh

cipher - mcwjaqo{s3zc4l_j3nkp0_symz34aoyx3?}
```
using this tool [enigma machine decoder](https://cryptii.com/pipes/enigma-machine) , we can get the flag 
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/dbcaf096-c383-4bfa-8706-0bdddf3781f8)

> FLAG - **rvcectf{g3rm4n_t3chn0_unbr34kabl3?}**
---
### _2. Art of Predictability_
##### _Category - Crypto_
So from looking at the description, the keywords being `predictability`, `pseudo-randomness` and `discontinuous piecewise linear equtions`  
All roads lead to _Linear Congruential Generator (LCG)_ algorithm 
It is basically a method to predict random numbers in a sequence. It involves using a mathematical formula that produces a sequence of numbers. If you know some of the numbers in the sequence, you can guess or predict the next ones based on the formula.
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/93e526ab-8acf-45a1-a629-f03855ab2a33)

from the given `chall.py` file, we have the output file for when the REDACTED string was the flag itself, so using these output files we must recover the flag by reverse engineering the LCG logic 
here's the script to solve it (takes ~2mins for  `11th Gen Intel Core i7 processor`, GTX )
```py
from Crypto.Util.number import *
from secrets import randbelow

c = 338
a = 599344352386808343942362083631315651051482988534356597436747398405546640205199809121068841381615007804381331920050949590140979658026
b = 307317214751347599334075359505552466068003792271858903864098631048566468631514439860252399045174604477237911810850498917212428762794
f_n = 504259001646375657358276756924765234401035694276027152328806917370271905660166868011782339898954517029361020484963852731183854103123
f_f_n = 62432874925401001222763334478046730690267119632892090392743820945840009053094217900368951837917352056063248402669850441353705595527
s = 696969

t = a * s + b

i = 1
while True:
    print("[*] current I:",i)
    guessed_prime = (t - f_n) // i
    if isPrime(guessed_prime) == 1:
        if (a * f_n + b) % guessed_prime == f_f_n:
            print("[*] Found prime number:", guessed_prime)
            p_str = long_to_bytes(guessed_prime - c)
            print(p_str)
            break
    i+=1
```
>It starts with a seed `s` and calculates a value `t` based on predefined constants `a` and `b`. Then, it iterates through a loop, incrementing a counter `i`, and calculates a guessed prime number based on a formula derived from `t`, `f_n`, and `i`. It checks if this guessed number is prime and satisfies specific conditions involving other constants `f_n` and `f_f_n`, which seem to be related to previous outputs of the LCG.
>Why these 2 conditions you may ask ?
>The first condition checks if the guessed prime number is actually prime, ensuring it's a valid candidate. The second condition verifies if a specific calculation involving the constants `a`, `b`, and previous LCG outputs `f_n` and `f_f_n` matches the expected value. Both conditions must be met to ensure that the guessed prime is both a prime number and follows the expected behavior of the LCG, thus confirming its validity as a reverse-engineered parameter.

To know more about it - refer to [this](https://en.wikipedia.org/wiki/Linear_congruential_generator) 
> FLAG - **rvcectf{p5eUd0r4nDom_num53r_g3ner4t0rs_4re_pr3d1ct4bl3}** 
---
### _3. Unscramble_
##### _Category - Rev_
>Cerggl zhpu abguvat gb fnl, whfg qvir va zna

On doing `rot13` u get :
`Pretty much nothing to say, just dive in man`
It's a `java source file` with some simple logic
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/dfe18c37-480c-4b72-a6e6-eda90544e0c7)

- first, `xor` `knownEncryptedFlag` with key `09` 
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/f3632492-02f3-479b-a2ed-371085e0742c)

Now using this [cyberchef recipe](https://gchq.github.io/CyberChef/#recipe=From_Hex('Space')ROT13(true,true,false,1)From_Base64('A-Za-z0-9%2B/%3D',true,false)Reverse('Character')From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=NEYgNTMgMzEgNTEgNTkgNjkgNDkgNTYgNjEgNTYgNEQgNkMgN0EgNDQgNjMgNkEgNjQgNDYgNEMgNzkgNTYgNDcgNkUgMzEgNEMgNkMgNDkgMzQgNTQgNTUgNjcgNTkgNjQgNTQgMzUgNDQgNTggMzMgNTggMzUgNTEgNkIgNkYgMzUgNTEgNkEgNjMgN0EgNjMgNTUgNDkgNDQgNTkgNDcgNkYgMzAgNEMgMzEgNkYgNkUgNjQgNDYgMzEgN0E) , we can get the flag with the above result as input 

![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/481c3575-1eb2-48af-b332-6e0ae2229a3a)

>FLAG - **flag{st4ndard_op3rat1ons_w1th_rev}**
---
### _4. Confidential leak_
##### _Catgeory - Web_
>In shadows deep, where secrets hide, Credentials leaked, our worlds collide. Paths we trace, in search of light, To find what's lost, and set things right.

hints from the description were :
- `worlds collide` - hash collision
- `paths we trace` - look for endpoints to discover the creds leak
So, we run a `gobuster` scan with common wordlist of URL endpoints.
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/0b1e8b3f-83dc-4267-9dc9-def41d1374ed)

Well, unfortunately even `.git` was exposed 🗿
and all of you took advantage of that and found the flag through `server.js` but here's the intended solve :
so we can see that the `/script` endpoint gives `200 OK` status, so head over to `https://confidential-leak.rvcechalls.xyz/script` and we get :
```js
var express = require('express');
var app = express();
var port = process.env.PORT || 9898;
var crypto = require('crypto');
var bodyParser = require('body-parser')
var salt = 'somestring';
var iteration = /// some number here;
var keylength = // some number here;

app.post('/login', function (req, res) {
    var username = req.body.username;
    var password = req.body.password;
    if (username !== 'joemama') {
        res.send('Username is wrong');
        return;
    }
    if (crypto.pbkdf2Sync(password, salt, iteration, keylength).toString() === hashOfPassword) {
        if (password === 'plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd') {
            // some logic here and return something
        } else {
            // return flag here
        }
    } else {
        res.send('Password is wrong');
    }
});
```
Trying creds `joemama:plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd` doesnt work
PBKDF2 uses HMAC and HMAC has an interesting property: if a supplied key is longer than the block size of the hash function that’s being used, it uses the hash of the key rather than the key itself.
you can read in depth about this from the following references :
[reference1](https://mathiasbynens.be/notes/pbkdf2-hmac)
[reference2](https://crypto.stackexchange.com/questions/15218/is-pbkdf2-hmac-sha1-really-broken) 
So we find a password which has the same hash as the leaked password

```js
──(kali㉿kali)-[~/Downloads]
└─$ echo -n 'plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd' | sha1sum | xxd -r -p
eBkXQTfuBqp'cTcar&g*
```
So we use `eBkXQTfuBqp'cTcar&g*` as the password and we get the flag.
> FLAG - **flag{d1d_i_ju5t_w1tness_a_h4sh_c0ll1sion??}**
---
### _5. Et-tu-brutus_
##### _Category - Web_
>In the lands between, a secret path lies hidden from the eyes of ordinary adventurers. Only the true Bearer of the key can unveil this path and unlock the ancient secrets held within.

So we do normal recon on the link, we have no attack vector whatsoever, so we do a `gobuster scan`
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://et-tu-brutus.rvcechalls.xyz/ -w /usr/share/wordlists/dirb/common.txt  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://et-tu-brutus.rvcechalls.xyz/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/protected            (Status: 200) [Size: 1295]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
On visiting `/protected` endpoint, it says `Looks like you fell to the tyranny of Messmer's flame` , so let's keep this info aside for now.
Open it up in burpsuite, in response we can see the `Authorization bearer token`
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/775a501c-a6fd-45aa-8600-1dcc1e3b4797)

```
Authorization bearer:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcxNzg3ODYzMSwianRpIjoiMmIyNDQ3OGEtNTUyYi00NTkyLWEwODctM2I2NjkzZWVhNWM4IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MCwibmJmIjoxNzE3ODc4NjMxLCJjc3JmIjoiZTMxMWMxZmEtM2E1ZC00MGI4LThlZDYtNGE1ZDkyZDg4ZDNlIiwiZXhwIjoxNzE3ODc5NTMxfQ.21sPV_2hO9oj4WD5xf9rYFk9ZjILzKqOl3Z9Mbn28zc
```
Let's decode this in [https://jwt.io/](https://jwt.io/) 
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/03d7e15b-274d-4850-85f9-0d6679b270fa)

Now try a few things, and submit token to `/protected` endpoint should be the thought process
- `fresh: false` to `fresh: true` - doesn't work
- `sub: 0` to `sub: 1` - works

But we need to bruteforce the `jwt authorization bearer token` for the `secret key` and update the token
We can install `jwt-cracker` from this link - [jwt-cracker install](https://github.com/lmammino/jwt-cracker) 
```
──(kali㉿kali)-[~]
└─$ jwt-cracker -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcxNzg0MjYyOCwianRpIjoiYTg2M2JkMmItNmIxMC00OWU1LTg2NmItYmI5MGVmZGIxMTk2IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MCwibmJmIjoxNzE3ODQyNjI4LCJjc3JmIjoiNjgwMmU2OTItOTEwMC00ZTY5LTkxYjMtYzA2ZDJlMWM5NTliIiwiZXhwIjoxNzE3ODQzNTI4fQ.tl0Wgp3QN9wGwvFRFA3d9F8ySCJlJoznz07Bc8Igzak -a 1234567890 
SECRET FOUND: 1337
Time taken (sec): 0.297
Total attempts: 20000
```
Now updated token consists of :
-  `sub: 0` to `sub: 1` - ✅
-  secret key = `1337` - ✅
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/d3046f3a-ca7a-4ff2-b1ad-efeb39f47e07)

Now just add the updated token as header to requests on `/protected` endpoint and see response, the flag will be there

![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/373ce2ac-d04e-41f5-9aa7-98f10d6c00eb)

> FLAG - **flag{M35m3r_1mpA13D}**
---
### _6. The Flying Beast_
##### _Category - OSINT_
>The vehicle which is used for transportation of the destructive medium range ramjet supersonic weapon was bought by the Indian army in `2006` and it's unique ID is `008649` and a letter `M` is assigned to this vehicle for internal adminisrative purposes. find out the number plate of this vehicle and then you have the flag. Flag format - flag{number plate}

So, many of you thought immediately that it is an actual vehicle whose image is to be found with the number plate matching the description, but actually it was an hypothetical vehicle number i made up and gave info about it in description
reference link is :
[military number plate format](https://www.team-bhp.com/news/explained-defence-vehicles-india-how-read-their-number-plates) 
[quora link](https://www.quora.com/What-is-the-meaning-of-Indian-Army-vehicle-registration-plates) - this quora thread clearly breaks down the format of number plate

Now from all this info, we can construct the number plate (yes, including ↑ as well)
This challenge was made to raise awareness that military vehicles have a different number plate format altogether.
> FLAG - **flag{↑06R008649M}**
---
### _7. The Astronaut's Enigma_
##### _Category - Forensics_
From the challenge description, we can deduce that there there is a security threat to India and we are tasked with finding out what Captain Vikram communicated back to ISRO from space and we are given the secret message along with a `.wav` audio file.

From the theme of challenge, we can say it revolves around transmission of information from space to earth and this was done using `Slow Scan Television` , which was originally used to transmit images via radio signals from the moon and back.
We will be using an application called `QSSTV` to perform this 
```python
$ sudo apt-get install qsstv
$ pactl load-module module-null-sink sink_name=virtual-cable
$ pavucontrol # A GUI will pop-up, go to the "Output Devices" tab to verify that you have the "Null Output" device
$ qsstv # The program GUI will pop-up, go to "Options" -> "Configuration" -> "Sound" and select the "PulseAudio" Audio Interface $ # Back in the pavucontrol GUI, select the "Recording" tab and specify that QSSTV should capture audio from the Null Output
$ paplay -d virtual-cable message.wav
```
In the `qsstv` GUI , select `Auto Slant` and `Autosave`, sensitivity as `normal` and mode as `auto` 
Alternatively, can also git clone and install [sstv automatic solver](https://github.com/colaclanth/sstv) and save all that grunt work. 
Now from the `png` image after completion, we get a key `keyisisroslowscans` and this is the key used for decoding from `TEA encryption` - [Tiny Encryption Algorithm](https://www.a.tools/Tool.php?Id=96) , more about it [here](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) 
> `secretmessage.txt` is encrypted using TEA cipher 
> on decoding with the key we get the flag
> FLAG - **rvcectf{ch1n4_s3cret_s4t3ll1tes_c4reful}**
---
### _8. TheChinesePhilosopher_
##### _Category - Forensics_
A `.gif` file was given wherein some part of the flag was feintly visible but went off quickly, so we can extract all the frames and browse the right frame with the partial flag - [gif frames extractor](https://ezgif.com/split/ezgif-4-8922bd3b11.gif) 
> We get 1st part - `flag{m4yb3_th3_un1v3r53_`

Now I dont know why many of y'all assumed this partial flag was the full flag because there clearly is no `}` in the frame.
Look into the `metadata` and we can find a `katbin link` 
https://katb.in/nenujuhoxay
this contains some chinese looking characters, do `ROT 8000` of it from 
[ROT 8000 decoder](https://rot8000.com/Index) 
we get 2nd part of flag `w4s_ju5t_a_5imul4t10n}`

>FLAG - **flag{m4yb3_th3_un1v3r53_w4s_ju5t_a_5imul4t10n}**
---
### _9. Noise pollution_
##### _Category - Forensics_
We have a hazy looking image with a lot of noise, the way to solve is `stereogram solver` 
Now theres 2 ways - through `stegsolve`, go to stereogram solver and move the offset till `90` OR through some random online `stereogram solver tool`

We love making everything easy so let's choose online tool - [online tool](https://piellardj.github.io/stereogram-solver/) 
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/5ca5308f-c74d-4408-b095-268d286a981b)


> FLAG - **flag{n0i5e_reV34l_Ftw}**
---
### _10. Lawliet's Successor Beyond_
##### _Catgeory - Steganography_
The title itself indicates `LSB` and it's a `jpg` image, you must've probably tried a lot of tools but in the end only one matters and it's `jsteg`
You can install it seeing the steps from - [jsteg installation](https://wiki.bi0s.in/steganography/jsteg/) 

After this it's just a simple command 
```
┌──(kali㉿kali)-[~/Downloads]
└─$ jsteg reveal chall.jpg  
flag{th3_be5t_det3ct1ve_0n_pl4neT_e4rTh}
```
>FLAG - **flag{th3_be5t_det3ct1ve_0n_pl4neT_e4rTh}**
---
### _11. Cartoon Network_
##### _Category - Steganography_
This challenge surprisingly didn't have any solve for a long time until hint was given, description was based on `powerpuff girls` and a `.wav` file of their theme song was given 
It indicates the tool - `OpenPuff Steganography tool` 
hint given was:
`powerPUFF girls 3.30 are OP` - the `3.30` was updated later because there seemed to be an issue with the latest `4.01` version of `OpenPuff tool` and it threw an error while tryna unhide.
You can find the download link for 3.30 version here - [3.30 install link](https://portableapps.com/node/26847) 

3 keys were given in description and they had to be entered in the same order for an optimum `hamming distance` and we would obtain the flag. 
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/b0008900-6b58-4f4a-9587-91f7452d0d36)


>A = powerpuffgirls
   B = sugarspice
   C = andeverythingnice

>FLAG - **flag{Th4nk5_f0r_h3lp1ng_th3_p0w3rpuFF_gurl5}**
---
### _12. Doodle Dilemma_
##### _Category - Miscellaneous_
This challenge was inspired from `IITBCTF '23 qualifiers` challenge whose writeup I have made before - [writeup link](https://github.com/BipinRajC/CTF-Writeups/tree/main/IITBCTF%20Qualifiers/Find%20find%20!!%20(QR%20repair))  
references:
[blog reference](https://merri.cx/qrazybox/help/examples/basic-example.html)
[online QR repair tool](https://merri.cx/qrazybox/) 
Everything is the same, just that flag is different 
>FLAG - **rvcectf{8o8_th3_bu1ld3r}**
---
### _13. Ethereal_
##### _Category - Miscellaneous_
>Deposit, Deploy and Explore

We're given a link to a `react app` where we can connect to our `crypto wallet` like `metamask` and then deploy an instance of the smart contract.

>Note: Unfortunately, the js files for this challenge were exposed and most of them just got the flag from js files 

But intended solve was:
First we get some `eth` from - [sepolia ether faucet](https://cloud.google.com/application/web3/faucet/ethereum/sepolia) by entering our wallet address to suffice for the gas fees for deploying the smart contract.
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/da51f5c9-39cf-4136-beea-e8b40c64ae4e)

After successful deployment, it displays the `contract address`, now we head over to [sepolia testnet explorer](https://sepolia.etherscan.io/) and enter the address.
There we get the most recent transaction hash with the timestamp, click on more details -> View input data -> View as UTF-8 
![image](https://github.com/BipinRajC/CTF-Writeups/assets/112572356/ff23c360-8b42-4659-beb1-33a33b4f7901)

Here, we can see the flag 
>FLAG - **flag{4lway5_vi3w_data_1n_all_f0rmats_98098}**
----

