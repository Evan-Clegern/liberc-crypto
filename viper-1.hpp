#ifndef erclib_viper_included
#define erclib_viper_included

#include <vector>
#include <array>
#include <cassert>
#include <bitset>
#include <string>

typedef unsigned char byte;
typedef std::vector<unsigned char> bytevec;
typedef std::array<bytevec, 2> vecpair;

namespace ERCLIB {
	namespace VIPER1 {
		namespace funcs {
			//Two different, invertible half-round functions
			extern const bytevec reverseVector(const bytevec input);
			extern const byte inverseKeyMod(const byte i);
			extern const vecpair revmultEnc(const bytevec input1, const bytevec input2, const byte a, const byte b);
			extern const vecpair revmultDec(const bytevec input1, const bytevec input2, const byte a, const byte b);
			extern const vecpair arxEnc(const bytevec input1, const bytevec input2, const byte a, const byte b);
			extern const vecpair arxDec(const bytevec input1, const bytevec input2, const byte a, const byte b);
			extern const bytevec roundFunction(bytevec diff, const byte key);
			extern const bytevec add(const bytevec to, const bytevec rnd);
			extern const bytevec diff(const bytevec left, const bytevec right);
			extern const vecpair midXOR(const bytevec left, const bytevec right, const byte lK, const byte rK);
			extern const vecpair XORvecs(const vecpair l, const vecpair r);
			extern const vecpair permuteEnc(const vecpair in, const byte key);
			extern const vecpair permuteDec(const vecpair in, const byte key);
		}
		extern const vecpair round_enc(const vecpair in, const bool Func, const bytevec* key, const byte keyStart);
		extern const vecpair round_dec(const vecpair in, const bool Func, const bytevec* key, const byte keyStart);
		extern const vecpair cycle_enc(const vecpair in, const bytevec* key, const std::vector<std::bitset<8>> schedule);
		extern const vecpair cycle_dec(const vecpair in, const bytevec* key, const std::vector<std::bitset<8>> schedule);
		extern const bytevec encrypt(const bytevec input, const bytevec key, const bytevec IV);
		extern const bytevec decrypt(const bytevec input, const bytevec key, const bytevec IV);
	}
	extern const std::string convertBytesToStr(const bytevec N);
	extern const bytevec encryptData_VIPER1(const bytevec Plaintext, const bytevec Key, const bytevec IV);
	extern const bytevec decryptData_VIPER1(const bytevec Ciphertext, const bytevec Key, const bytevec IV);
}

#endif
