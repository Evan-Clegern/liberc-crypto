# liberc-crypto

This is a custom cryptography library, containing three security algorithms.

### Not Another Cryptographic Hash Algorithm
As the name alludes, NACHA is my crack at making a cryptographically-secure hashing algorithm.
It is inspired by Keccak (SHA-3) and MD5, utilizing a sponge-like system and several permutation devices.

### VIPER
This is a block cipher, using the less-common Lai-Massey Scheme to provide its schedule for encryption.
It suffers from a lack of Diffusion (256 bits are changed in a 1,920 bit message when 1 bit of plaintext is modified), 
and is built using a Cipher Block Chaining mode and with a few tweaks to the Lai-Massey Scheme.
It has a 60-byte (480-bit) key size and a 12-byte (96-bit) block size.

### KOBRA
This is a new type of encryption algorithm - one I have dubbed "Calycryptographic."
This comes from the greek root 'Calyp' for Hide, and then from Cryptography.
Although the kobra.cpp file describes it in more depth, the overview is that it runs encryption based on a cipher function
and a Base Message, of which are then used to create an Encrypted Hidden Message. It uses a minimum-length password of 12
bytes (96 bits) and a message that is up to the length of Base Message - 1, along with a one-byte IV. The cipher function
uses a one-byte block size in Cipher Block Chaining to amplify changes, hence the minimalistic IV. This could see a good
use in extended Deniable Encryption, assuming I actually had the time to work on it.
#### Basic Operation
1. A copy of the Base Message *B* is encrypted using the Password and IV, forming *B'*
2. The Hidden Message *H* has each of its bytes XORed with the IV, forming *H'*
3. *B'* and *H'* are XORed together, forming *S*
4. Trim *S* to the length of *H'*
5. Encrypt *S* using the Password and IV, forming *S'*
6. Return *S'* as the operation's output.

## Implementation
To use my little library, you need to run the makefile as `make` and then let it compile.

### g++ (Recommended)
Add the following flags:
`-I[PATH_OF_ERCLIB] -Wl,-rpath=[PATH_OF_ERCLIB] -L[PATH_OF_ERCLIB] -lerc-crypto`
at the **end of your G++ command,** unless you want to copy `liberc-crypto.so` to your `lib` directory (then cut the -Wl and -L). Then just include the individual headers (kobra.hpp, viper.hpp or nacha.hpp) or the full liberc-crypto.hpp one for all three, plus a few utilities.

## Changelog
Sep 16
Runtime uint <--> ushort issues in loops has been corrected in NACHA and KOBRA. Library is now passing CodeQL analysis.
