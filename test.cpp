#include "liberc-crypto.hpp"
#include <iostream>

int main() {
	std::string TestText = "According to all known laws of aviation, there is no way that a bee should be able to fly. Its wings are too small to get its fat little body off the ground. The bee, of course, flies anyway. Because bees don’t care what humans think is impossible.";
	bytevec Hashable = ERCLIB::strToBVec(TestText);
	bytevec Hash128 = ERCLIB::hashData128(Hashable);
	bytevec Hash128E = ERCLIB::hashData128E(Hashable);
	std::cout << "Hashes of the funny text:\n";
	for (byte i : Hash128) {
		std::cout << int(i) << ' ';
	}
	std::cout << '\n';
	for (byte i : Hash128E) {
		std::cout << int(i) << ' ';
	}
	std::cout << '\n';
	bytevec Key = ERCLIB::hashData512E(Hashable); // VIPER key is 480 bits, so we drop a few bytes here (4, to be exact)
	Key.pop_back();
	Key.pop_back();
	Key.pop_back();
	Key.pop_back();
	// IV Size is 12 bytes (96 bits), trim Hash128.
	Hash128.pop_back();
	Hash128.pop_back();
	Hash128.pop_back();
	Hash128.pop_back();
	
	std::cout << std::hex;
	
	std::cout << "Encrypting...\n";
	auto Encrypted = ERCLIB::encryptData(Hashable, Key, Hash128);
	for (byte i : Encrypted) {
		std::cout << int(i) << ' ';
	}
	std::cout << "\nDecrypting...\n";
	auto Decrypted = ERCLIB::decryptData(Encrypted, Key, Hash128);
	for (byte i : Decrypted) {
		std::cout << int(i) << ' ';
	}
	std::cout << "\nOriginal Data:\n";
	for (byte i : Hashable) {
		std::cout << int(i) << ' ';
	}
	std::cout << '\n' << ERCLIB::bvecToStr(Decrypted);
}
