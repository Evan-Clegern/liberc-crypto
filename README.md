# liberc-crypto

This is a custom cryptography library, containing three security algorithms.  [![CodeQL](https://github.com/Evan-Clegern/liberc-crypto/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/Evan-Clegern/liberc-crypto/actions/workflows/codeql-analysis.yml)

### NACHA (Not *Another* Cryptographic Hash Algorithm)
As the name alludes, NACHA is my crack at making a cryptographically-secure hashing algorithm.
It is inspired by Keccak (SHA-3) and MD5, utilizing a sponge-like system and several permutation devices.
#### Basic Overview
Assuming three permutation functions, *PA(x)*, *PB(x)*, *PC(x)*, a 'mix' function *M(x, tog)*, an 'intertwine' function *ITW(xa, xb, c)*, input message *m*, output capacity *z*, block size A *ba*, and block size B *bb*.
1. Split *m* into a vector of vectors, of size *bb*, padding partial blocks with portions of the vector **{11h, 22h, 33h, 44h, 55h, 66h, 77h}**, to make *m'*. Maintain a blank vector of vectors, *m".
2. For each vector in *m'* as *x*, toggle between appending just *PC(x)* to *m"*, and also appending *M(x, 0)* and *PA(M(x, 1))* to *m"*, starting at **only** *PC(x)* and toggling after that.
3. Append *M(m, 1)* to *m"*; then, set *m'* to a "fused" version of *m"* that is then split into blocks of size *ba*. Clear *m"*.

#### This section is still in-progress. I will be updating this NACHA description when I can.


### VIPER-1
This is a block cipher, using the less-common Lai-Massey Scheme to provide its schedule for encryption. Unfortunately,
it suffers from a lack of Diffusion (256 bits are changed in a 1,920 bit message when 1 bit of plaintext is modified), 
and is built using a Cipher Block Chaining mode and with a modified Lai-Massey Scheme. 
It has a 60-byte (480-bit) key size and a 12-byte (96-bit) block size.
#### Basic Encryption Operation
Assuming Permutation Function *P(x, k)*, Round Function *R(x, k)*, Half-Round Function *H(x, k1, k2)*,
12-byte Message *m*,  Key *K* and Key Offset *n*.
1. Split *m* into *l* and *r*
2. Perform *P(l, **K**n)* and *P(r, **K**n)* to create *l'* and *r'*
3. Perform Half-Round *H(l', **K**n, **K**n+1)* and *H(r', **K**n, **K**n+1)*, forming *L* and *R*
4. XOR *L* to ***K**n+2*, and *R* to ***K**n+3*, forming *L'* and *R'*
5. Subtract *R'* from *L'* to form *S*
6. Perform *R(S, **K**n+4)* to form *S'*
7. Add *S'* to *L'* and *R'*, forming *L''* and *R''*
8. Perform *P(L'', **K**n+4)* and *P(L'', **K**n+4)* to form *EL* and *ER*.
9. Return pair *E* , consisting of *EL* and *ER*.


### KOBRA
This is a new type of encryption algorithm - one I have dubbed "Calycryptographic."
This comes from the greek root 'Calyp' for Hide, and then from Cryptography.
Although the kobra.cpp file describes it in more depth, the overview is that it runs encryption based on a cipher function
and a Base Message, of which are then used to create an Encrypted Hidden Message. It uses a minimum-length password of 12
bytes (96 bits) and a message that is up to the length of Base Message - 1, along with a one-byte IV. The cipher function
uses a one-byte block size in Cipher Block Chaining to amplify changes, hence the minimalistic IV. This could see a good
use in extended Deniable Encryption, assuming I actually had the time to work on it.
#### Basic Encryption Operation
1. A copy of the Base Message *B* is encrypted with ARX, using the Password and IV, forming *B'*.
2. The Hidden Message *H* has each of its bytes XORed with the IV, forming *H'*
3. *B'* and *H'* are XORed together, forming *S*
4. Trim *S* to the length of *H'*
5. Encrypt *S* using the Password and IV through ARX, forming *S'*
6. Return *S'* as the operation's output.

## Implementation
To use my little library, you need to run the makefile as `make` and then let it compile. For the test file, afterwards run `make test`.

### g++
Add the following flags:
`-I[PATH_OF_ERCLIB] -Wl,-rpath=[PATH_OF_ERCLIB] -L[PATH_OF_ERCLIB] -lerc-crypto`
at the **end of your G++ command,** unless you want to copy `liberc-crypto.so` to your `lib` directory (then cut the -Wl and -L). Then just include the individual headers (kobra.hpp, viper.hpp or nacha.hpp) or the full liberc-crypto.hpp one for all three, plus a few utilities.

## Changelog
#### Sep 16 '21
Runtime uint <--> ushort issues in loops has been corrected in NACHA and KOBRA. Library is now passing CodeQL analysis.
#### Oct 18 '21
Tweaks to documentation of algorithms.
#### Oct 27 '21
Added a side-project I'd been working on that allows the creation and management of Substitution and Permutation boxes.
#### Aug 25 '22
Added some memory sanitation and conservation to the NACHA program.
#### Sep 8 '22
Added a testing file and corrected a bug found by CodeQL.


## Test File Output
When compiled and run, the test file should return some data:
### Top-Of-Output Hashes
`Hashes of the funny text:`

`40 94 198 36 159 135 47 153 217 42 148 140 212 14 50 236 `

`24 12 230 210 42 36 74 30 75 44 39 30 37 53 157 32`

### Encryption Output
`30 1b 86 e0 9f 34 6a 97 51 e3 e2 ff bc cd 89 3e 61 dc 65 b7 f0 a3 7c fb e2 d9 ea d4 8e af 4 c1 58 13 4e 79 54 c9 bd 6d 99 8b f0 6 d2 59 48 56 eb f7 4e bf 2e 48 94 44 b9 8f 27 37 6d 9d 2e a5 77 99 71 b5 61 c9 71 40 3d 8e 43 15 c1 af be 9c 69 1a 9c 60 61 4 d4 a2 52 c1 10 3 16 a3 14 89 1f aa 4e f 4f c5 1 f5 3c 17 4c 95 86 cc 52 e3 5 d2 84 e d6 69 55 e9 5e 10 9b e9 de 14 76 ae 31 d0 3b e8 5 52 65 55 f4 22 a2 f3 ef 81 ba c6 af 38 5b 5d d8 30 d0 c5 21 f0 d2 ee df dd a6 eb c9 83 75 a5 1e 10 a5 9b 38 4d c fe d6 9b 7d b9 88 e4 b5 7a e6 2 43 4c 10 c0 ff f0 e4 87 2a cf 71 6 30 c2 71 c4 eb 49 3f 6c c8 f e3 71 52 cc 9c 69 5b cf 68 5e d6 8f 36 23 f0 5a 86 8 ff f 23 c1 fb 92 4e b0 3d eb e3 54 7b 30 e8 fc 97 6 d7 23 6f 14 57 6c 9e 1a f8 a4 c1 9b e8 96 6c e2 9d 6 9c 9d 89 46 1 6a ` 
### Final Output (Decrypted-to-string)
`According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway. Because bees don’t care what humans think is impossible.`


This is the general test case for NACHA (128 and 128E) and VIPER -- the opening part of the Bee Movie.
