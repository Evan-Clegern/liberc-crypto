#ifndef erclib_kobra_included
#define erclib_kobra_included

#include <vector>
#include <cmath>
#include <cassert>

typedef unsigned short ushort;
typedef unsigned char byte;

namespace ERCLIB {
	namespace KOBRA {
		namespace Low {
			extern const std::vector<byte> cipherEncrypt(std::vector<byte> plaintext, std::vector<byte> key, byte IV);
			extern const std::vector<byte> cipherDecrypt(std::vector<byte> ciphertext, std::vector<byte> key, byte IV);
			extern const std::vector<byte> XOR(std::vector<byte> mainText, std::vector<byte> secondText);
			extern const std::vector<byte> XOR(std::vector<byte> text, byte what);
		}
		struct keyPair {
			std::vector<byte> EncryptKey, ExtractKey;
			byte IV;
		};
		extern const keyPair encryptFrom(std::vector<byte> calycryptBody, std::vector<byte> key, std::vector<byte> message, byte IV);
		extern const std::vector<byte> decryptFrom(std::vector<byte> calycryptBody, keyPair data);
	}
}



#endif
