# IITBCTF QUALIFIERS


## Find find !! (QR repair)

> Nilabha bought a new processor and was comparing its performance using Cinebench, some problem happened, and the image did not render properly. Figure out which processor Nilabha was testing.
>
> Flag format: iitbCTF{}
>
> Author: ravenroy
>
>[`cinebench.png`](./assets/cinebench.PNG)

Tags: _Miscellaneous_

## Solution

We should manually construct a QR pixel by pixel on [`QRazybox`](https://merri.cx/qrazybox/) that matches the QR given in `cinebench.png` and the tool will automatically predict the pattern and reconstruct the missing part and we can extract info out of it from the site itself

Refer this - [`Reference article`](https://merri.cx/qrazybox/help/examples/basic-example.html)

New project -> new blank QR code -> select 25x25(ver 2) and module size 15px

Now looking at the png fill out the pixels with `black` and `white` both `manually` and on doing so we get : 

![Alt text](./assets/iitbQR1.PNG)

Note - grey blocks means pixels are unknown

Now go to Tools -> Extract QR information

![Alt text](./assets/iitbQR2.png)

In final decoded string we can see the flag obtained

FLAG : `iitbCTF{Shakti_PR0cessOr}`
