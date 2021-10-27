#ifndef ERCrypt_CustomConcepts
#define ERCrypt_CustomConcepts

#include <array>
#include <cassert>
#include <map>

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char byte;

namespace ERCLIB {
namespace CryptConcepts {
	
	template<byte blockSize> std::array<byte, blockSize> performXOR(std::array<byte, blockSize> a, std::array<byte, blockSize> b) noexcept {
		std::array<byte, blockSize> temp;
		for (byte i=0;i<blockSize;i++) {
			temp[i] = a[i] ^ b[i];
		}
		return temp;
	}
	template<byte blockSize, byte keySize> std::array<byte, blockSize> performXOR(std::array<byte, blockSize> a, std::array<byte, keySize> b) noexcept(keySize < blockSize) {
		assert(keySize < blockSize);
		std::array<byte, blockSize> temp;
		byte keyIndex=0;
		for (byte i=0;i<blockSize;i++) {
			temp[i] = a[i] ^ b[keyIndex];
			if (keyIndex == keySize - 1) keyIndex = 0; else keyIndex++;
		}
		return temp;
	}
	
	template<byte blockSize> std::array<byte, blockSize> performXOR(std::array<byte, blockSize> a, byte p1, byte p2) {
		std::array<byte, blockSize> temp;
		bool toggle = 1;
		for (byte i=0;i<blockSize;i++) {
			temp[i] = a[i] ^ (toggle ? p1 : p2); //Flips between 'p1' and 'p2'
			toggle = !toggle;
		}
		return temp;
	}
	
	namespace Substitution {
		struct Ref8 {
			byte val;
			explicit Ref8(byte n) : val(n) {};
			bool operator<(const Ref8& b) const noexcept {return (this->val < b.val);};
		};
		struct Ref16 {
			byte valL, valR;
			explicit Ref16(byte l, byte r) : valL(l), valR(r) {};
			bool operator<(const Ref16& b) const noexcept {return ((this->valR < b.valR) && (this->valL < b.valL)) || (this->valL < b.valL);};
		};
		
		// SBox8<16, &function> modifier(key)
		// C++ doesn't like templates in compiled libraries, so.. we use these in the header.
		// Sorry!
		
		template<ushort keySize, Ref8 (*mainFunc)(std::array<byte,keySize>,Ref8)> class SBox8 {
			std::array<byte, keySize> keyVector;
			std::map<Ref8, Ref8> primary, secondary;
		public:
			Ref8 operator()(Ref8 value, bool forward = 1) {return forward ? (this->primary.at(value)) : (this->secondary.at(value));};
			
			const ushort getKeySize() const noexcept {return this->keySize;}
			const std::map<Ref8, Ref8>* getForwardTable() const {return &this->primary;};
			const std::map<Ref8, Ref8>* getBackwardTable() const {return &this->secondary;};
			
			explicit SBox8(std::array<byte, keySize> key) : keyVector(key) {
				if (key.size() != keySize) throw std::invalid_argument("Key size mismatch - SBox8!");
				std::map<Ref8, bool> existTable;
				for (byte i=0;i<255;i++) {
					Ref8 k(i);
					Ref8 n = mainFunc(key, k);
					if (existTable.count(n) != 0) throw std::runtime_error("Function provided to SBox8 is NOT deterministic!");
					existTable.emplace(n, 1);
					primary.emplace(k, n);
				}
			}
		};
		template<ushort keySize, Ref16 (*mainFunc)(std::array<byte,keySize>,Ref16)> class SBox16 {
			std::array<byte, keySize> keyVector;
			std::map<Ref16, Ref16> primary, secondary;
		public:
			Ref16 operator()(Ref16 value, bool forward = 1) {return forward ? (this->primary.at(value)) : (this->secondary.at(value));};
			
			const ushort getKeySize() const noexcept {return this->keySize;}
			const std::map<Ref16, Ref16>* getForwardTable() const {return &this->primary;};
			const std::map<Ref16, Ref16>* getBackwardTable() const {return &this->secondary;};
			
			explicit SBox16(std::array<byte, keySize> key) : keyVector(key) {
				if (key.size() != keySize) throw std::invalid_argument("Key size mismatch - SBox16!");
				std::map<Ref16, bool> existTable;
				for (byte a=0;a<255;a++) {
					for (byte i=0;i<255;i++) {
						Ref16 k(a, i);
						Ref16 n = mainFunc(key, k);
						if (existTable.count(n) != 0) throw std::runtime_error("Function provided to SBox16 is NOT deterministic!");
						existTable.emplace(n, 1);
						primary.emplace(k, n);
					}
				}
			}
			
		};
		
	}
	
	namespace Permutation {
		
		//! Debugged
		template<byte blockSize> std::array<byte, blockSize> rotate2s(std::array<byte, blockSize> bytes, bool left, byte lvl) {
			assert(lvl <= 7);
			std::array<byte, blockSize> tmp;
			for (byte i=0; i < (blockSize - 1); i+=2) {
				if (left) {
					byte A = bytes[i];
					byte B = bytes[i+1];
					//    -- A   B --
					// 12345678 9ABCDEFG
					//       ROT 2
					// 3456789A BCDEFG12
					//    -- A   B --
					tmp[i] = (A << lvl) | (B >> (8 - lvl));
					tmp[i+1] = (B << lvl) | (A >> (8 - lvl));
				} else {
					byte A = bytes[i];
					byte B = bytes[i+1];
					tmp[i] = (A >> lvl) | (B << (8 - lvl));
					tmp[i+1] = (B >> lvl) | (A << (8 - lvl));
				}
			}
			return tmp;
		}
		template<byte blockSize> std::array<byte, blockSize> rotateAll(std::array<byte, blockSize> bytes, bool left, byte lvl) {
			assert(lvl <= 7);
			std::array<byte, blockSize> tmp; tmp.fill(0);
			if (left) {
				byte next = bytes[1];
				for (byte i=0; i < (blockSize -1); i++) {
					tmp[i] = (bytes[i] >> lvl) | (next << (8 - lvl));
					next = bytes[i + 2];
				}
				tmp[blockSize - 1] = (bytes[blockSize - 1] >> lvl) | (bytes[0] << (8 - lvl));
			} else {
				byte last = bytes[blockSize - 1];
				for (byte i=0; i < (blockSize); i++) {
					tmp[i] = (bytes[i] << lvl) | (last >> (8 - lvl));
					last = bytes[i];
				}
				//tmp[blockSize - 1] = (bytes[blockSize - 1] << lvl) | (bytes[0] >> (8 - lvl));
				//The error here was an Off-By-One.
				//Why is it that ... 
			}
			return tmp;
		}
		template<byte blockSize> std::array<byte, blockSize> rearrange(std::array<byte, blockSize> main, std::array<byte, blockSize> table, bool forward = 1) {
			std::array<byte, blockSize> temp;
			if (forward) {
				for (byte i=0;i<blockSize;i++) {
					temp[ table[i] ] = main[i];
				}
			} else {
				for (byte i=0;i<blockSize;i++) {
					temp[i] = main[ table[i] ];
				}
			}
			return temp;
		}
		
		/********!
		 * @param [in] blockSize
		 * 		The data block size of which it operates upon. Must be an even number within 8 <= x <= 254
		 * @param [in] stA_flip
		 * 		Whether to perform the first rotation left or right.
		 * @param [in] stB_flip
		 * 		Whether to perform the second rotation left or right.
		 * @param [in] stC_flip
		 * 		Whether to perform the third rotation left or right.
		 * @param [in] stA_inv
		 * 		Whether or not to invert every other byte after the first rotation.
		 * @param [in] stB_inv
		 * 		Whether or not to invert every other byte after the second rotation.
		 * @param [in] stC_inv
		 * 		Whether or not to invert every other byte after the third rotation.
		 * @param [in] stA_rot
		 * 		The distance to rotate all the bits for the first rotation group.
		 * @param [in] stB_rot
		 * 		The distance to rotate all the bits for the second rotation group.
		 * @param [in] stC_rot
		 * 		The distance to rotate all the bits for the third rotation group.
		 * @param [in] stE_rot
		 * 		The distance to rotate all the bits for the END rotation group.
		 * 
		 * <byte blockSize, bool stA_flip,  byte stA_rot, bool stB_flip,
			byte stB_rot, bool stC_flip, byte stC_rot, byte stE_rot>
		 ********/
		template<byte blockSize, bool stA_flip,  byte stA_rot, bool stB_flip,
		byte stB_rot, bool stC_flip, byte stC_rot, byte stE_rot> class SimplePermuter {
			std::array<byte, blockSize> stageA_placement;
			std::array<byte, blockSize> stageB_placement; //this the dynamic one
			std::array<byte, blockSize> stageC_placement;
			
		public:
			const std::array<byte, blockSize> getStageA() const noexcept {
				return this->stageA_placement;
			}
			const std::array<byte, blockSize> getStageB() const noexcept {
				return this->stageB_placement;
			}
			const std::array<byte, blockSize> getStageC() const noexcept {
				return this->stageC_placement;
			}
			explicit SimplePermuter(byte key1, byte key2, byte IV) {
				
				static_assert( blockSize >= 8 );
				static_assert( (blockSize & 1) == 0);
				static_assert(stA_rot <= 7);
				static_assert(stB_rot <= 7);
				static_assert(stC_rot <= 7);
				static_assert(stE_rot <= 7);
				
				assert(IV <= blockSize);
				
				//A and C translations are "static" to the size in use
				
				ushort amult = blockSize >> 1;
				if (amult & 1) amult+=2+blockSize; else amult+=1+blockSize;
				ushort cmult = ((blockSize+2) >> 1) + blockSize;
				if (!(cmult & 1)) amult+=1;
				byte adda = (amult >> 2), addc = (cmult >> 1) + 4;
				
				for (byte i=0;i<blockSize;i++) {stageA_placement[i]=(adda+(amult*i)) % blockSize; stageC_placement[i]=(addc+(cmult*i)) % blockSize;}
				
				ushort bmult1 = ((key1 & IV) ^ (key1 >> 1) ^ (~key1 << 2)) >> 1;
				ushort bmult2 = (blockSize + (blockSize >> 2)) >> 1;
				if (bmult1 & 1) bmult1+=4; else bmult1+=5;
				if (bmult2 & 1) bmult2+=1; else bmult2+=2;
				byte addb = (key2 ^ (bmult1 >> 4)) + (key2 >> 2);
				
				for (byte i=0; i<blockSize;i++) stageB_placement[i] = byte((addb + uint(bmult1 * i) + uint(bmult2 * i)) % blockSize);
			}
			/*
			 * A (B (C (D (x)))) = n
			 * D'(C'(B'(A'(n)))) = x
			 * 
			 * so E = rearrange, T = two's, R = rotate
			 * R1(E1(x))
			 * 
			 */
			std::array<byte, blockSize> operateForward(std::array<byte, blockSize> input, std::array<byte,6> key) {
				std::array<byte, blockSize> temp = input;
				
				temp = rotate2s<blockSize>(temp, 1, 4);
				
				
				temp = rearrange<blockSize>(temp, this->stageA_placement, stA_flip);
				temp = rotateAll<blockSize>(temp, 0, stA_rot);
				for (byte i=0;i<blockSize;i+=2) {temp[i]^=key[1];temp[i+1]^=key[2];}
				temp = rotate2s<blockSize>(temp, 1, stA_rot);
				temp = rotateAll<blockSize>(temp, 1, stA_rot);
				
				temp = rearrange<blockSize>(temp, this->stageB_placement, stB_flip);
				temp = rotateAll<blockSize>(temp, 1, stB_rot);
				for (byte i=0;i<blockSize;i+=2) {temp[i]^=key[3];temp[i+1]^=key[4];}
				temp = rotate2s<blockSize>(temp, 0, stB_rot);
				temp = rotateAll<blockSize>(temp, 0, stB_rot);
				
				temp = rearrange<blockSize>(temp, this->stageC_placement, stC_flip);
				temp = rotateAll<blockSize>(temp, 0, stC_rot);
				for (byte i=0;i<blockSize;i+=2) {temp[i]^=key[5];temp[i+1]^=key[0];}
				temp = rotate2s<blockSize>(temp, 1, stC_rot);
				temp = rotateAll<blockSize>(temp, 1, stC_rot);
				
				for (byte i=0;i<blockSize;i++) {temp[i]^=0xA5;}
				temp = rotateAll<blockSize>(temp, 0, stE_rot);
				temp = rotate2s<blockSize>(temp, 1, stE_rot);
				temp = rotateAll<blockSize>(temp, 1, stE_rot);
				
				return temp;
			}
			
			std::array<byte, blockSize> operateBackward(std::array<byte, blockSize> input, std::array<byte,6> key) {
				std::array<byte, blockSize> temp = input;
				
				temp = rotateAll<blockSize>(temp, 0, stE_rot);
				temp = rotate2s<blockSize>(temp, 0, stE_rot);
				temp = rotateAll<blockSize>(temp, 1, stE_rot);
				for (byte i=0;i<blockSize;i++) {temp[i]^=0xA5;}
				
				
				temp = rotateAll<blockSize>(temp, 0, stC_rot);
				temp = rotate2s<blockSize>(temp, 0, stC_rot);
				for (byte i=0;i<blockSize;i+=2) {temp[i]^=key[5];temp[i+1]^=key[0];}
				temp = rotateAll<blockSize>(temp, 1, stC_rot);
				temp = rearrange<blockSize>(temp, this->stageC_placement, !(stC_flip));
				
				temp = rotateAll<blockSize>(temp, 1, stB_rot);
				temp = rotate2s<blockSize>(temp, 1, stB_rot);
				for (byte i=0;i<blockSize;i+=2) {temp[i]^=key[3];temp[i+1]^=key[4];}
				temp = rotateAll<blockSize>(temp, 0, stB_rot);
				temp = rearrange<blockSize>(temp, this->stageB_placement, !(stB_flip));
				
				temp = rotateAll<blockSize>(temp, 0, stA_rot);
				temp = rotate2s<blockSize>(temp, 0, stA_rot);
				for (byte i=0;i<blockSize;i+=2) {temp[i]^=key[1];temp[i+1]^=key[2];}
				temp = rotateAll<blockSize>(temp, 1, stA_rot);
				temp = rearrange<blockSize>(temp, this->stageA_placement, !(stA_flip));
				
				
				temp = rotate2s<blockSize>(temp, 0, 4);
				
				return temp;
			}
		};
		
	}
}
}



#endif
