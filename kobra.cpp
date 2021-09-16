/********!
 * @file kobra.cpp
 * 
 * 
 * @date
 * 		14 September 2021
 * 
 * @brief
 * 		Base for the KOBRA Calycryptographic Encryption algorithm
 * 
 * @details
 * 		Curiously, KOBRA was originally considered "Acrostic" encryption. This is
 * 		a gross misclassification. Acrostic refers to the first letter of each word,
 * 		sentence or paragraph, for example.
 * 
 * 		As such, a new term was needed. Calycryptography is the new term - a combination
 * 		between cryptography and the Greek word 'calyp', for cover. This gives the meaning,
 * 		in a "pure sense," of "hidden cover writing."
 * 
 * 		Like its name alludes, Calycryptography involves encrypting a hidden message in
 * 		"covered" reference to an unchanged, original message and a key. This involves
 * 		using a simple cipher for the encryption and then performing an XOR between an
 * 		encrypted copy of the Base Message and the Hidden Message, before encrypting
 * 		that output again.
 * 
 * 		You may ask, "Why is this unique?" Calycryptography is a method of semi-concealment
 * 		that could be easily paired with Steganography to conceal an encrypted message 
 * 		inside of a base, otherwise-unchanged one. I don't know the full range of
 * 		applications, but I do believe that the KOBRA Calycryptographic Algorithm would
 * 		be a stable protocol to encrypt messages that require both a password and - or at
 * 		least, an excerpt of - original data. 
 * 
 * 		Problems about the security of Calycryptography are something I have already
 * 		taken into consideration. The first of which is - with this original KOBRA
 * 		algorithm, at least - that the output message is the same length as the
 * 		secret message is. This could lead to a side-channel vulnerability. The second
 * 		is that it could be possible to reveal some form of useful information if one
 * 		were to XOR the output message with the original data (section) that was used
 * 		to encrypt with, although, since the output message is encrypted, and a copy
 * 		of the original is encrypted as well prior to the deriviation, this may not be
 * 		a significant issue. Finally, there may be some vulnerability in the usage of
 * 		one-byte Cipher Block Chaining with the encryption function, however, my
 * 		preliminary tests did not reveal a significant problem.
 * 
 * 		
 * 
 * @copyright
 * 		2021 Evan Clegern <evanclegern.work@gmail.com>
 *
 * 		This program is free software; you can redistribute it and/or modify
 * 		it under the terms of the GNU General Public License as published by
 * 		the Free Software Foundation, either version 3 of the License, or
 * 		(at your option) any later version.
 * 
 * 		This program is distributed in the hope that it will be useful,
 * 		but WITHOUT ANY WARRANTY; without even the implied warranty of
 * 		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * 		GNU General Public License for more details.
 * 
 * 		You should have received a copy of the GNU General Public License
 * 		along with this program.  If not, see <https://www.gnu.org/licenses/>
 * 
 * 
 ********/

#include "kobra.hpp"

namespace ERCLIB {
namespace KOBRA {
	namespace Low {
		/********!
		 * @brief
		 * 			Runs a simple and lightweight Add-Rotate-XOR cipher on an input
		 * 			which also operates in a one-byte Cipher Block Chaining mode, which
		 * 			helps to cipher the data more securely.
		 * 
		 * @param [in] plaintext
		 * 			Main text to encrypt.
		 * @param [in] key
		 * 			Encryption key (at least 96 bits) to use for encryption.
		 * @param [in] iv
		 * 			Initialization Vector byte for the CBC mode.
		 * 
		 * @returns
		 * 			Ciphered byte vector.
		 ********/
		const std::vector<byte> cipherEncrypt(std::vector<byte> plaintext, std::vector<byte> key, byte IV) {
			// Add-Rotate-XOR cipher in one-byte Cipher Block Chaining mode
			assert(key.size() >= 12);
			assert(key.size() <= plaintext.size());
			byte XORblk = IV;
			std::vector<byte> temp;
			ushort tempIndex = 0, size = key.size();
			for (uint i = 0; i < plaintext.size(); i++) {
				byte work = plaintext[i] ^ XORblk;
				byte w2 = (work + key[tempIndex]);
				w2 = ((w2 >> 3) | (w2 << 5)); // 12345678 --> 67812345
				w2 ^= (w2 ^ key[tempIndex]) ^ (w2 ^ ~key[size - tempIndex]);
				temp.push_back(w2);
				XORblk = w2 >> 1; //! Preserve top bit
				if (tempIndex == size - 1) tempIndex = 0; else tempIndex++;
			}
			return temp;
		}
		/********!
		 * @brief
		 * 			Runs a simple and lightweight Add-Rotate-XOR cipher on an input
		 * 			which also operates in a one-byte Cipher Block Chaining mode, which
		 * 			helps to cipher the data more securely; this decrypts a byte vector.
		 * 
		 * @param [in] ciphertext
		 * 			Main input to decrypt.
		 * @param [in] key
		 * 			Encryption key (at least 96 bits) to use for the decryption.
		 * @param [in] iv
		 * 			Initialization Vector byte for the CBC mode.
		 * 
		 * @returns
		 * 			Decrypted byte vector.
		 ********/
		const std::vector<byte> cipherDecrypt(std::vector<byte> ciphertext, std::vector<byte> key, byte IV) {
			assert(key.size() >= 12);
			assert(key.size() <= ciphertext.size());
			byte XORblk = IV;
			std::vector<byte> temp;
			ushort tempIndex = 0, size = key.size();
			for (uint i = 0; i < ciphertext.size(); i++) {
				byte work = ciphertext[i];
				byte w2 = work ^ ( (work ^ key[tempIndex]) ^ (work ^ ~key[size - tempIndex]) ); // UNDO the XOR stage
				w2 = ((w2 >> 5) | (w2 << 3)); // UNDO the ROT stage
				w2 = (w2 - key[tempIndex]) ^ XORblk; // UNDO the ADD stage and the CBC stage
				temp.push_back(w2);
				XORblk = work >> 1; // Prepare next CBC value
				if (tempIndex == size - 1) tempIndex = 0; else tempIndex++;
			}
			return temp;
		}
		
		/********!
		 * @brief
		 * 			Performs a "mix" XOR between a (presumably) larger input and a 
		 * 			second one.
		 * 
		 * @param [in] mainText
		 * 			Larger-sized input for the 'XOR cipher.'
		 * @param [in] secondText
		 * 			Smaller-sized (unrepeated) input for the 'XOR cipher.'
		 * 
		 * @returns
		 * 			Differential byte vector.
		 ********/
		const std::vector<byte> XOR(std::vector<byte> mainText, std::vector<byte> secondText) {
			assert(mainText.size() >= secondText.size());
			ushort second = 0, sSize = secondText.size();
			std::vector<byte> temp;
			for (byte i : mainText) {
				if (second == sSize) {
					temp.push_back(i);
				} else {
					temp.push_back(i ^ secondText[second]);
					second++;
				}
			}
			return temp;
		}
		
		/********!
		 * @brief
		 * 			XORs a message in respect to a single byte.
		 * 
		 * @param [in] text
		 * 			Main message to act upon.
		 * @param [in] what
		 * 			Byte to XOR the message to.
		 * 
		 * @returns
		 * 			XORed message.
		 ********/
		const std::vector<byte> XOR(std::vector<byte> text, byte what) {
			std::vector<byte> temp;
			for (byte i : text) {
				temp.push_back( i ^ what );
			}
			return temp;
		}
	}
	// keypair is EncryptKey, ExtractKey (bytevecs) and IV (byte)
	//! Encrypt Message
	const keyPair encryptFrom(std::vector<byte> calycryptBody, std::vector<byte> Key, std::vector<byte> message, byte IV) {
		auto ready = Low::XOR(message, IV);
		
		auto to = Low::cipherEncrypt(calycryptBody, Key, IV);
		
		ready = Low::XOR(to, ready);
		
		std::vector<byte> Fmesg;
		ushort CNT = 0, SIZE = message.size();
		for (byte i : ready) {
			if (CNT == SIZE) break;
			Fmesg.push_back(i);
			CNT++;
		}
		
		ready = Low::cipherEncrypt(Fmesg, Key, IV);
		
		keyPair temp;
		temp.EncryptKey = Key;
		temp.ExtractKey = ready;
		temp.IV = IV;
		
		return temp;
	}
	//! Extract Message
	const std::vector<byte> decryptFrom(std::vector<byte> calycryptBody, keyPair data) {
		auto to = Low::cipherEncrypt(calycryptBody, data.EncryptKey, data.IV);
		
		auto ready = Low::cipherDecrypt(data.ExtractKey, data.EncryptKey, data.IV);
		
		auto XORed = Low::XOR(to, ready);
		
		std::vector<byte> Fmesg;
		ushort CNT = 0, SIZE = data.ExtractKey.size();
		for (byte i : XORed) {
			if (CNT == SIZE) break;
			Fmesg.push_back(i);
			CNT++;
		}
		
		return Low::XOR(Fmesg, data.IV);
	}
	
}
}
