/********!
 * @file viper-1.cpp
 * 
 * @copyright
 * 		Copyright 2021 Evan Clegern <evanclegern.work@gmail.com>
 * 
 * 		This program is free software; you can redistribute it and/or modify
 * 		it under the terms of the GNU General Public License as published by
 * 		the Free Software Foundation; either version 3 of the License, or
 * 		(at your option) any later version.
 * 
 * 		This program is distributed in the hope that it will be useful,
 * 		but WITHOUT ANY WARRANTY; without even the implied warranty of
 * 		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * 		GNU General Public License for more details.
 * 
 *		You should have received a copy of the GNU General Public License
 * 		along with this program.  If not, see <https://www.gnu.org/licenses>
 * 
 * 
 * @details
 * 		VIPER-1 uses a Lai-Massey scheme, with both Permutation functions and
 * 		Add-Rotate-XOR functions for the Half-Round, and a simple Affine
 * 		function for the Round function.
 * 
 * 		VIPER-1 is a simple block cipher with a sixty-byte (480-bit)
 * 		key and with a block size of 24 bytes (192 bits). It was
 * 		designed with resistance to timing based attacks in the
 * 		simpler functions, and possesses simple resistances to
 * 		basic Electronic Code-Book vulnerability by reversing
 * 		parts of the output and by utilizing a single-byte
 * 		initialization vector for its scheduling and for its 
 * 		round function. It uses a slightly-unconventional form of
 * 		the Lai-Massey scheme, where it alternates between the
 * 		half-round function, and performs direct XORs before
 * 		performing the round function operation. It contains, in
 * 		the encrypted version, a simple header, of which contains
 * 		a magic number (0xA55A - which looks cool in binary) and
 * 		then a number of NULL bytes, followed by said NULL bytes.
 * 		This is only present if the data is decrypted properly,
 * 		and is for removing said padding to extract the original
 * 		message. The padding data is added prior to even the
 * 		first round of encryption, given its fixed-width block
 * 		sizes. VIPER has fairly high Confusion but fairly low
 * 		Diffusion based on Shannon's model.
 * 
 *  		- Confusion is provided by the Lai-Massey scheme
 *  		 in general, and especially by the large key size.
 *  		- Diffusion is partially provided by the two half
 *  		 round functions; Reverse-Multiply adds more of it
 *  		 than Add-Rotate-XOR, but the relative Input to
 *  		 Output bit positions remain the same. A newer
 *  		 addition to attempt and mitigate this was a 
 *  		 permutation function. Given a 1,920 bit message,
 *  		 changing one bit of the plaintext affected 256 
 *  		 of the bits. This is not the diffusion seen in
 * 			 high-efficiency, high-security algorithms, but
 *  		 is still enough for the purposes of VIPER.
 * 
 * 		However, given its rather large key size, fairly
 * 		large block size, use of initialization vector and the
 * 		layout for basic Key Scheduling, it is assumed to be a
 * 		safe, deterministic algorithm for low to mid-security,
 * 		general-purpose and high-efficiency symmetric encryption.
 * 
 * 
 */

#include "viper-1.hpp"
namespace ERCLIB {
	namespace VIPER1 {
		namespace funcs {
			inline const bytevec reverseVector(const bytevec input) {
				bytevec temp(input.size(), 0);
				uint tind = input.size() - 1;
				for (byte i : input) {
					temp[tind] = i;
					tind--;
				}
				return temp;
			}
			inline const byte inverseKeyMod(const byte i) {
				//Modular inverse
				byte n = 1; bool good = 0;
				for (byte T = 1; T < 255; T++) { //Time-constant operation
					if (good) {ushort for_time = (i * n) % 256; for_time--;}
					if ((i  * n) % 256 == 1 ) good = 1; else n++;
				}
				return n;
			}
			//! toggles between 'revmult' and 'arx' for the half-round function used
			//! which hRf we start with, and then how we order our mixes, are from the key.
			
			//! network should be balanced (12 bytes and 12 bytes) so
			//! VIPER has a block size 24 bytes (192 bits)
			//! also, each round should use 2B for hRf, 2B for mid-round XOR and 1B for Rf
			//! basically, XOR the blocks with a key byte before adding the Round function's result
			
			// uses five key bytes per round
			// key schedulued mixes and which half-Round we start with
			// use 12 simple rounds, so....
			// keysize = 60 bytes (480 bits)
			// blocksize = 24 bytes (192 bits) with padding being every 3 key bytes being XORed
			// So, no vector should exceed 12 bytes in size
			
			//! solved a bug with this where it wasn't actually ensuring the bytes were invertible,
			//! and then a half-fix I made didn't work at all. Now it's all good.
			//! SOLVED ANOTHER @bug - THIS WOULD HAVE A "BARRELING" AFFECT BECAUSE THE INVERSES WEREN'T TESTED! ALL GOOD NOW.
			inline const vecpair revmultEnc(const bytevec input1, const bytevec input2, const byte a, const byte b) {
				// Note: if one key is correct, then half the data is correct. KEEP IN MIND.
				assert(input1.size() == input2.size());
				byte kA = a, kB = b;
				if (inverseKeyMod(kA) == 255) kA >>= 2;
				if (inverseKeyMod(kB) == 255) kB >>= 2;
				if (kA == 0) {kA = 1;} 
				if (kB == 0) {kB = 1;}
				if (!(kA & 1)) kA += 1;  // This is a catch, in case we can't use our key very well  (even #s cannot be inverted for this)
				if (!(kB & 1)) kB += 1;
				bytevec A = reverseVector(input1), B = input2, c, d;
				for (byte i : A) {
					c.push_back(ushort((ushort(i) * kA) + (b >> 4)) % 256);
				}
				for (byte i : B) {
					d.push_back(ushort((ushort(i) * kB) + (a >> 4)) % 256);
				}
				vecpair N = {d, c};
				return N;
			}
			inline const vecpair revmultDec(const bytevec input1, const bytevec input2, const byte a, const byte b) {
				assert(input1.size() == input2.size());
				byte kA = a, kB = b;
				if (inverseKeyMod(kA) == 255) kA >>= 2; // First insurance that the key is usable
				if (inverseKeyMod(kB) == 255) kB >>= 2;
				if (kA == 0) {kA = 1;} 
				if (kB == 0) {kB = 1;}
				if (!(kA & 1)) kA += 1;  // This is a catch, in case we can't use our key very well (even #s cannot be inverted for this)
				if (!(kB & 1)) kB += 1;
				byte ia = inverseKeyMod(kA), ib = inverseKeyMod(kB);
				bytevec A = input2, B = input1, c, d;
				for (byte i : A) {
					c.push_back(ushort((ushort(i) - (b >> 4)) * ia) % 256);
				}
				for (byte i : B) {
					d.push_back(ushort((ushort(i) - (a >> 4)) * ib) % 256);
				}
				vecpair N = {reverseVector(c), d};
				return N;
			}
			inline const vecpair arxEnc(const bytevec input1, const bytevec input2, const byte a, const byte b) {
				// Add rotate XOR
				// Add a, rotate by a certain factor, XOR b
				// this doesn't swap the "effective" left and right, because the rotation style sorta does already.
				byte BaseS = a + b;
				bytevec iA, iB;
				assert(input1.size() == input2.size());
				for (byte i=0; i<12;i++) {
					byte A = input1[i] + a, B = input2[i] + a, rot = (short(BaseS) + short(i)) % 8;
					if (rot == 0) {
						iA.push_back(B ^ b);
						iB.push_back(A ^ b);
					} else {
						iA.push_back(((A >> rot) | (B << (8 - rot))) ^ b);
						iB.push_back(((B >> rot) | (A << (8 - rot))) ^ b);
					}
					
				}
				vecpair N = {iA, iB};
				return N;
			}
			inline const vecpair arxDec(const bytevec input1, const bytevec input2, const byte a, const byte b) {
				byte BaseS = a + b;
				bytevec iA, iB;
				assert(input1.size() == input2.size());
				for (byte i=0; i<12;i++) {
					byte A = input1[i] ^ b, B = input2[i] ^ b, rot = (short(BaseS) + short(i)) % 8;
					if (rot == 0) {
						iA.push_back(B - a);
						iB.push_back(A - a);
					} else {
						byte Ar = (A << rot); // first half
						byte Br = (B << rot);
						Ar |= (B >> (8 - rot));
						Br |= (A >> (8 - rot));
						iA.push_back(Ar - a);
						iB.push_back(Br - a);
					}
				}
				vecpair N = {iA, iB};
				return N;
			}
			inline const bytevec roundFunction(const bytevec diff, const byte key) {
				// XORs key-and-input "duality modulo" with a blended rotation and XOR of the input and key.
				bytevec tmp;
				for (byte i : diff) {
					//! @bug  In some cases, the Key byte is equal to the Diff byte, causing a divide-by-zero.
					byte divi = (key ^ i);
					if (divi == 0) divi = 1;
					tmp.push_back( ((key ^ i) & ((i >> 4) | (key << 4))) ^ ((key * i) % divi) );
				}
				return tmp;
			}
			inline const bytevec add(const bytevec to, const bytevec rnd) {
				bytevec tmp;
				assert(to.size() == rnd.size());
				for (byte i = 0; i < 12; i++) {
					tmp.push_back(to[i] + rnd[i]);
				}
				return tmp;
			}
			inline const bytevec diff(const bytevec left, const bytevec right) {
				bytevec tmp;
				assert(left.size() == right.size());
				for (byte i = 0; i < 12; i++) {
					tmp.push_back(left[i] - right[i]);
				}
				return tmp;
			}
			inline const vecpair midXOR(const bytevec left, const bytevec right, const byte lK, const byte rK) {
				bytevec lv, rv;
				assert(left.size() == right.size());
				for (byte i : left) {
					lv.push_back(i ^ lK);
				}
				for (byte i : right) {
					rv.push_back(i ^ rK);
				}
				vecpair N = {lv, rv};
				return N;
			}
			const vecpair XORvecs(const vecpair l, const vecpair r) {
				bytevec lv, rv;
				assert(l[0].size() == r[0].size()); assert(l[1].size() == r[1].size());
				for (byte i = 0; i < 12; i++) {
					lv.push_back(l[0][i] ^ r[0][i]);
				}
				for (byte i = 0; i < 12; i++) {
					rv.push_back(l[1][i] ^ r[1][i]);
				}
				vecpair N = {lv, rv};
				return N;
			}
			//! Permutation box-like function
			//! Splits the input bytes in half and sends them across two byte vectors,
			//! and then iterates *forward* through the left one and *backward* through the right
			//! and placing bits in the output vector unevenly. Then it performs an 'iterative
			//! XOR' with the key provided, performing a CBC-like operation on the right side
			//! of the data, and finally doing a swap-and-rotation permutation.
			//! this adds 256 bits of dependence in a 1,920-bit message (2:15 ratio).
			const vecpair permuteEnc(const vecpair in, const byte key) {
				// Two-way permutation function
				// Does split and XOR  to permute some of the bits of our input
				bytevec lv, rv; //Divides each byte in two, placing one in either side.
				for (byte i = 0; i < 12; i++) {
					byte L = in[0][i] ^ key;
					byte R = in[1][i];
					lv.push_back((L >> 4) | (R << 4)); // NL = R4 R5 R6 R7 L0 L1 L2 L3
					rv.push_back((L << 4) | (R >> 4)); // NR = L4 L5 L6 L7 R0 R1 R2 R3
				}
				vecpair N;
				for (byte i = 0; i < 12; i++) { //Mix them around from opposite sides
					byte L = lv[i];
					byte R = rv[11 - i];
					N[0].push_back((R >> 2) | (L << 6)); // NL = L6 L7 R0 R1 R2 R3 R4 R5
					N[1].push_back((L >> 2) | (R << 6)); // NR = R6 R7 L0 L1 L2 L3 L4 L5
				}
				for (byte i = 0; i < 12; i++) {
					N[0][i] ^= key + byte((12 * ushort(i)) % (key + 1));
					N[1][i] ^= ~key - byte((15 *  ushort(i)) % (key + 1));
				}
				for (byte i = 0; i < 12; i++) {
					byte L = N[0][i];
					N[1][11- i] ^= (key ^ L) - i;
					N[1][i] ^= L + i;
				}
				byte shiftB = key % 8;
				for (byte i = 0; i < 12; i++) {
					byte R = N[1][i], L = N[0][i], shift = (shiftB + i) % 8;
					N[0][i] =  ((R >> shift) | (L << (8 - shift))) ^ key;
					N[1][i] = ~((L >> shift) | (R << (8 - shift)));
				}
				return N;
			}
			const vecpair permuteDec(const vecpair in, const byte key) {
				bytevec lv, rv; //Divides each byte in two, placing one in either side.
				//Also implement a Cipher Block Chaining-like mode here?
				vecpair N; N[0].reserve(12); N[1].reserve(12);
				byte shiftB = key % 8;
				for (byte i = 0; i < 12; i++) {
					byte R = ~in[1][i], L = in[0][i] ^ key, shift = (shiftB + i) % 8;;
					/*                                            //if shift = 2
					N[0][i] = (R >> shift) | (L << (8 - shift));  //L6 L7 R0 R1 R2 R3 R4 R5
					N[1][i] = (L >> shift) | (R << (8 - shift));  //R6 R7 L0 L1 L2 L3 L4 L5
					*/
					N[0][i] = ((L >> (8 - shift)) | (R << shift));
					N[1][i] = ((R >> (8 - shift)) | (L << shift));
				}
				for (byte i = 0; i < 12; i++) {
					byte L = N[0][i];
					N[1][11- i] ^= (key ^ L) - i;
					N[1][i] ^= L + i;
				}
				for (byte i = 0; i < 12; i++) {
					byte L = N[0][i] ^ (key + byte((12 *  ushort(i)) % (key + 1)));
					lv.push_back(L);
					rv.push_back(N[1][i] ^ (~key - byte((15 *  ushort(i)) % (key + 1))));
				}
				N[0].clear(); N[1].clear(); 
				N[0].reserve(12); N[1].reserve(12);
				for (byte i = 0; i < 12; i++) {
					byte L = lv[i];
					byte R = rv[i];
					N[0][i] = ((L >> 6) | (R << 2));
					N[1][11 - i] = ((R >> 6) | (L << 2));
				}
				lv.clear(); rv.clear();
				for (byte i = 0; i < 12; i++) {
					byte L = N[0][i];
					byte R = N[1][i];
					lv.push_back(((R >> 4) | (L << 4)) ^ key);
					rv.push_back(((R << 4) | (L >> 4)));
				}
				//! @bug the Front and Back halves of the data seem switched, but modifying the step above didn't help.
				//! Fixed this - forgot that the 'right' output is flipped during the encryption-side.
				N = {lv, rv};
				return N;
			}
		}
		inline const vecpair round_enc(const vecpair in, const bool Func, const bytevec* key, const byte keyStart) {
			//Add 5 to keyStart's parent when done

			vecpair newer = funcs::permuteEnc(in, key->at(keyStart));
			if (Func) {
				newer = funcs::arxEnc(newer[0], newer[1], key->at(keyStart), key->at(keyStart + 1));
			} else {
				newer = funcs::revmultEnc(newer[0], newer[1], key->at(keyStart), key->at(keyStart + 1));
			}
			vecpair XORed = funcs::midXOR(newer[0], newer[1], key->at(keyStart + 2), key->at(keyStart  + 3));
			bytevec Diff = funcs::diff(XORed[0], XORed[1]);
			bytevec Round = funcs::roundFunction(Diff, key->at(keyStart + 4));
			XORed = {funcs::add(XORed[1], Round), funcs::add(XORed[0], Round)};
			return funcs::permuteEnc(XORed, key->at(keyStart + 4));
		}
		inline const vecpair round_dec(const vecpair in, const bool Func, const bytevec* key, const byte keyStart) {
			//Subtract five from keyStart's parent when done
			
			// if EncKeyStart = 0, then it ended at 4
			// Round == 4
			// XOR   == 2, 3
			// Func  == 0, 1
			vecpair J = funcs::permuteDec(in, key->at(keyStart + 4));
			bytevec Diff = funcs::diff(J[1], J[0]); //Un-Flip
			bytevec Round = funcs::roundFunction(Diff, key->at(keyStart +4));
			vecpair XORed = {funcs::diff(J[1], Round), funcs::diff(J[0], Round)};
			XORed = funcs::midXOR(XORed[0], XORed[1], key->at(keyStart + 2), key->at(keyStart + 3));
			if (Func) {
				XORed = funcs::arxDec(XORed[0], XORed[1], key->at(keyStart ), key->at(keyStart + 1));
			} else {
				XORed = funcs::revmultDec(XORed[0], XORed[1], key->at(keyStart ), key->at(keyStart + 1));
			}
			return funcs::permuteDec(XORed, key->at(keyStart));
		}
		const vecpair cycle_enc(const vecpair in, const bytevec* key, const std::vector<std::bitset<8>> schedule) {
			assert(key->size() == 60); assert(in[0].size() == in[1].size()); assert(schedule.size() == 2);
			//20 rounds which use the key in full.
			//4 rounds which use preset (5  0xA5);
			bytevec r4n(5, 0xA5);
			//I intended this to have explicit additional permutations.
			vecpair N = round_enc(in, schedule[0][0], key, 0);
			N = round_enc(N, schedule[0][1], key, 5);
			N = round_enc(N, schedule[0][2], key, 10);
			N = round_enc(N, schedule[0][3], key, 15);
			N = round_enc(N, schedule[0][4], key, 20);
			N = round_enc(N, schedule[0][5], key, 25);
			N = round_enc(N, schedule[0][6], key, 30);
			N = round_enc(N, schedule[0][7], key, 35);
			
			N = round_enc(N, schedule[1][0], key, 40);
			N = round_enc(N, schedule[1][1], key, 45);
			N = round_enc(N, schedule[1][2], key, 50);
			N = round_enc(N, schedule[1][3], key, 55);
			
			N = round_enc(N, schedule[1][4], &r4n, 0);
			N = round_enc(N, schedule[1][5], &r4n, 0);
			N = round_enc(N, schedule[1][6], &r4n, 0);
			N = round_enc(N, schedule[1][7], &r4n, 0);
			return N;
		}
		const vecpair cycle_dec(const vecpair in, const bytevec* key, const std::vector<std::bitset<8>> schedule) {
			assert(key->size() == 60); assert(in[0].size() == in[1].size()); assert(schedule.size() == 2);
			//20 rounds which use the key in full.
			//4 rounds which use preset (5  0xA5);
			bytevec r4n(5, 0xA5);
			vecpair N = round_dec(in, schedule[1][7], &r4n, 0);
			N = round_dec(N, schedule[1][6], &r4n, 0);
			N = round_dec(N, schedule[1][5], &r4n, 0);
			N = round_dec(N, schedule[1][4], &r4n, 0);
			
			N = round_dec(N, schedule[1][3], key, 55);
			N = round_dec(N, schedule[1][2], key, 50);
			N = round_dec(N, schedule[1][1], key, 45);
			N = round_dec(N, schedule[1][0], key, 40);
			
			N = round_dec(N, schedule[0][7], key, 35);
			N = round_dec(N, schedule[0][6], key, 30);
			N = round_dec(N, schedule[0][5], key, 25);
			N = round_dec(N, schedule[0][4], key, 20);
			N = round_dec(N, schedule[0][3], key, 15);
			N = round_dec(N, schedule[0][2], key, 10);
			N = round_dec(N, schedule[0][1], key, 5);
			N = round_dec(N, schedule[0][0], key, 0);
			return N;
		}
		//! Redesigned this to: 1. have better scheduling 2. support Cipher-block chaining 3. fix encrypt/decrypt bug
		const bytevec encrypt(const bytevec input, const bytevec key, const bytevec IV) {
			assert(key.size() == 60); assert(input.size() >= 24);
			assert(input.size() % 24  == 0); assert(IV.size() == 12);
			//! Acquire preliminary scheduling matrix by doing a LOT of XORs.
			byte sA = key.at(0) ^ key[1] ^ key[2] ^ key[3] ^ key[4] ^ key[5] ^ key[6] ^ key[7];
			byte sB = key[8] ^ key[9] ^ key[10] ^ key[11] ^  key[12] ^ key[13] ^ key[14] ^ key[15];
			byte sC = key[16] ^ key[17] ^ key[18] ^ key[19] ^ key[20] ^ key[21] ^ key[22] ^ key[23];
			byte sD = key[24] ^ key[25] ^ key[26] ^ key[27] ^ key[28] ^ key[29] ^ key[30] ^ key[31];
			byte sE = key[32] ^ key[33] ^ key[34] ^ key[35] ^ key[36] ^ key[37] ^ key[38] ^ key[39];
			byte sF = key[40] ^ key[41] ^ key[42] ^ key[43] ^ key[44] ^ key[45] ^ key[46] ^ key[47];
			byte sG = key[48] ^ key[49] ^ key[50] ^ key[51] ^ key[52] ^ key[53] ^ key[54] ^ key[56];
			//! Define true scheduling matrix by using Modular multiplication and some more XORs
			byte sched1 = (((sA * sB) + sE) % 256) ^ key[57] ^ (sG & key[59]);
			byte sched2 = (((sC * sD) + sF) % 256) ^ key[58] ^ (sG & key[59]);
			//assert(0 == 1); //! this was to see where the segmentation fault was
			//! make it into booleans
			std::vector<std::bitset<8>> SchedMatrix = {sched1, sched2}; //sleazy little conversion
			
			// split up input into blocks
			std::vector<vecpair> Pairs; vecpair TempPair;
			byte Tl=0, Tr=0; bool Right = 0;
			for (byte i : input) {
				if (Right) {
					TempPair[1].push_back(i);
					Tr++;
					if (Tr == 12) {
						Right = 0; Tl = 0; Tr = 0;
						Pairs.push_back(TempPair);
						TempPair[0].clear(); TempPair[1].clear();
					}
				} else {
					TempPair[0].push_back(i);
					Tl++;
					if (Tl == 12) Right = 1;
				} 
			}
			bytevec Output1;
			vecpair last = {IV, funcs::reverseVector(IV)};
			for (vecpair E : Pairs) {
				assert(E[0].size() == 12);
				assert(E[1].size() == 12);
				vecpair N = funcs::XORvecs(E, last);
				N = cycle_enc(N, &key, SchedMatrix);
				last = funcs::permuteEnc(N, sched1 ^ sched2);
				for (byte i : N[0]) Output1.push_back(i);
				for (byte i : N[1]) Output1.push_back(i);
			}
			return Output1;
		}
		const bytevec decrypt(const bytevec input,  const bytevec key, const bytevec IV) {
			assert(key.size() == 60); assert(input.size() >= 24);
			assert(input.size() % 24  == 0); assert(IV.size() == 12);
			//! Acquire preliminary scheduling matrix by doing a LOT of XORs.
			byte sA = key.at(0) ^ key.at(1) ^ key.at(2) ^ key.at(3) ^ key.at(4) ^ key.at(5) ^ key.at(6) ^ key.at(7);
			byte sB = key.at(8) ^ key.at(9) ^ key.at(10) ^ key.at(11) ^  key.at(12) ^ key.at(13) ^ key.at(14) ^ key.at(15);
			byte sC = key.at(16) ^ key.at(17) ^ key.at(18) ^ key.at(19) ^ key.at(20) ^ key.at(21) ^ key.at(22) ^ key.at(23);
			byte sD = key.at(24) ^ key.at(25) ^ key.at(26) ^ key.at(27) ^ key.at(28) ^ key.at(29) ^ key.at(30) ^ key.at(31);
			byte sE = key.at(32) ^ key.at(33) ^ key.at(34) ^ key.at(35) ^ key.at(36) ^ key.at(37) ^ key.at(38) ^ key.at(39);
			byte sF = key.at(40) ^ key.at(41) ^ key.at(42) ^ key.at(43) ^ key.at(44) ^ key.at(45) ^ key.at(46) ^ key.at(47);
			byte sG = key.at(48) ^ key.at(49) ^ key.at(50) ^ key.at(51) ^ key.at(52) ^ key.at(53) ^ key.at(54) ^ key.at(56);
			//! Define true scheduling matrix by using Modular multiplication and some more XORs
			byte sched1 = (((sA * sB) + sE) % 256) ^ key.at(57) ^ (sG & key.at(59));
			byte sched2 = (((sC * sD) + sF) % 256) ^ key.at(58) ^ (sG & key.at(59));
			//! make it into booleans
			std::vector<std::bitset<8>> SchedMatrix = {sched1, sched2}; //sleazy little conversion
			
			// split up input into blocks
			std::vector<vecpair> Pairs; vecpair TempPair;
			byte Tl=0, Tr=0; bool Right = 0;
			for (byte i : input) {
				if (Right) {
					TempPair[1].push_back(i);
					Tr++;
					if (Tr == 12) {
						Right = 0; Tl = 0; Tr = 0;
						Pairs.push_back(TempPair);
						TempPair[0].clear(); TempPair[1].clear();
					}
				} else {
					TempPair[0].push_back(i);
					Tl++;
					if (Tl == 12) Right = 1;
				} 
			}
			bytevec Output;
			vecpair last = {IV, funcs::reverseVector(IV)};
			assert(last[1].size() == 12);
			for (vecpair E : Pairs) {
				vecpair N = cycle_dec(E, &key, SchedMatrix);
				N = funcs::XORvecs(N, last);
				last = funcs::permuteEnc(E, sched1 ^ sched2);
				for (byte i : N[0]) Output.push_back(i);
				for (byte i : N[1]) Output.push_back(i);
			}
			return Output;
		}
	}
	//! Idea for full implementation
	//! have a header chunk with three bytes, and then all necessary null bytes PRIOR to data - byte #1 and #2 are a magic number; #3 is the number of padded null bytes
	//! i.e. 0xA5 0x5A 0x02 0x00 0x00 {data} -  we only need to pad UP TO 21 bytes.

	const bytevec encryptData_VIPER1(const bytevec Plaintext, const bytevec Key, const bytevec IV) {
		byte NullBytes = 24 - ((3 + Plaintext.size()) % 24);
		bytevec headerTmp(NullBytes + 3, 0);
		headerTmp[0] = byte(0xA5);
		headerTmp[1] = byte(0x5A);
		headerTmp[2] = NullBytes;
		for (byte i : Plaintext) {
			headerTmp.push_back(i);
		}
		return VIPER1::encrypt(headerTmp, Key, IV);
	}
	const bytevec decryptData_VIPER1(const bytevec Ciphertext, const bytevec Key, const bytevec IV) {
		bytevec temp = VIPER1::decrypt(Ciphertext, Key, IV);
		assert(temp[0] == 0xA5); assert(temp[1] == 0x5A);
		byte Padding = temp[2];
		bytevec newer;
		for (uint i = Padding + 3; i < temp.size(); i++) {
			newer.push_back(temp[i]);
		}
		return newer;
	}
}
