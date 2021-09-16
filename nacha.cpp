/*
 * nacha.cpp  --> Library Extension for nacha.hpp
 * 
 * Copyright (c) August 2021 Evan R. Clegern <evanclegern.work@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 * 
 * 
 * 
 * 
 * 
 * This project may contain C++ Layouts that are known to the State of
 * California to cause Cancer, Birth Defects or other Reproductive Harm.
 */

#include "nacha.hpp"
/********!
 * @bug Segmentation errors with permuteA
 *  		Solution was that all of our 'Underflow' calculations were
 *  		bad - I forgot that modulo is how many leftovers of the divisor
 *  		there are. Solved it by doing (Divisor - (Input mod Divisor)).
 * 
 * @remark
 * 		Redesign made the algorithm much more Clock-efficient and is
 * 		still very stable (if not more) for cryptographic hashing.
 ********/
namespace ERCLIB {
namespace NACHA {
	namespace low {
		/********!
		 * @brief
		 * 			Permutation 'A' function, which effectively will
		 * 			return a double-size byte vector
		 * 
		 * @param [in] Input
		 * 			Byte vector to permute
		 * 
		 * @returns
		 * 			Byte vector, with the length of Input, rounded up to
		 * 			the nearest multiple of eight, times two.
		 * 
		 * @details
		 * 			@li Uses padding Hexspeak 'DEADBEEF' when making the
		 * 			input copy a multiple of eight
		 * 
		 * 			@li Bits are extracted from parent bytes, and placed
		 *			into output bytes based upon where their parent byte
		 * 			was in the blocks - the parent byte's index is solely
		 * 			how we determine the left-shifting necessary for the bit.
		 * 
		 * 			@li Once the original data is permuted, it will go
		 * 			through the permuted block from \e both ends, 
		 * 			performing a bit rotation and XOR on the bytes we
		 * 			take out, and then XORing that with the cumulative
		 * 			XOR of the input.
		 * 
		 * @exception std::invalid_argument
		 * 			If \c Input is empty, then there is no point in
		 * 			attempting to permute the filler bytes.
		 ********/
		inline std::vector<byte> permuteA(const std::vector<byte> &Input) {
			byte Underflow = 8 - (Input.size() % 8);
			std::vector<byte> tmp = Input;
			if (Underflow > 0) {
				std::vector<byte> append = {0xDE, 0xAD, 0xBE, 0xEF};
				byte cnt=0, app = 0;
				while (cnt < Underflow) {
					tmp.push_back(append[app]);
					if (app == 3) {app = 0;} else {app++;}
					cnt++;
				}
			} else if (tmp.size() == 0) {
				throw std::invalid_argument("No data provided to permuteA!");
			}
			uint nsize = tmp.size();

			std::vector<byte> out;
			//This loop: chunks per padded input
			byte totXOR = 0;
			for (uint c = 0; c < (nsize / 8); c++) {
				byte IND = c * 8;
				std::vector<byte> chunk(8, 0);
				//This loop: bytes per chunk
				for (byte i=0;i<8;i++) {
					byte n = tmp[IND + i];
					totXOR ^= n;
					//This loop: bits per byte
					for (byte B = 0; B < 8; B++) {
						bool bit = n & 1;
						n >>= 1;
						byte J = byte(0 + bit) << i;
						chunk[B] |= J;
					}
				}
				//This loop: move chunk to output
				for (byte i : chunk) {
					out.push_back(i);
				}
			}
			// This XORs each output byte to the 'inverse position' byte in the permuted "arch."
			// Ensure that, for larger inputs, their input chunks will not match up at all with their permuted chunks.
			// And if it's a smaller input, it'll at least occur in a different order.
			nsize = out.size();
			for (uint i=0; i < nsize - 1; i++) {
				uint ind = (nsize - 1) - i;
				if (ind >= nsize) {ind = (nsize - 1);}
				byte n = out.at(ind), j = out.at(i);
				
				out.push_back( ((n >> 4) | (j << 4)) ^ (~(j & n) ^ totXOR) );
			}
			return out;
		}
		
		
		/********!
		 * @brief
		 * 			Permutation 'B' function, which effectively will
		 * 			return a same-size byte vector
		 * 
		 * @param [in] Input
		 * 			Byte vector to permute
		 * 
		 * @returns
		 * 			Byte vector, with the length of Input, rounded up to 
		 * 			the nearest multiple of eight.
		 * 
		 * @details
		 * 			@li Uses padding Hexspeak 'FEEDC0DE' when making the
		 * 			input copy a multiple of eight
		 * 
		 * 			@li Bits are extracted from parent bytes, and are
		 * 			inserted to the output bytes based both on the
		 * 			bit's own index and the parent byte's index.
		 * 			This staggers which byte's bit takes the Most
		 * 			Significant Bit, and creates a rainbow-like
		 * 			pattern. The left bit shift is described as
		 * 			the parent byte's index, minus the bit's index
		 * 			in it, with 8 being added if necessary. This
		 * 			would place Byte 0, Bit 0 in O-Byte 0, Bit 0,
		 * 			but Bit 1 into O-Byte 1, Bit 7 (8 + (0 - 1) = 7).
		 * 			This allows for a more "shuffled" system of
		 * 			bit permutation.
		 * 
		 * @exception std::invalid_argument
		 * 			If \c Input is empty, then there is no point in
		 * 			attempting to permute the filler bytes.
		 ********/
		inline std::vector<byte> permuteB(const std::vector<byte> &Input) {
			byte Underflow = 8 - (Input.size() % 8);
			std::vector<byte> tmp = Input;
			//instead of appending 'DEADBEEF', we append 'FEEDC0DE'
			if (Underflow > 0) {
				std::vector<byte> append = {0xFE, 0xED, 0xC0, 0xDE};
				byte cnt=0, app = 0;
				while (cnt < Underflow) {
					tmp.push_back(append[app]);
					if (app == 3) {app = 0;} else {app++;}
					cnt++;
				}
			} else if (tmp.size() == 0) {
				throw std::invalid_argument("No data provided to permuteB!");
			}
			uint nsize = tmp.size();
			std::vector<byte> out;
			//This loop: chunks per input
			for (uint c = 0; c < (nsize / 8); c++) {
				byte IND = c * 8;
				std::vector<byte> chunk(8, 0);
				//This loop: bytes per chunk
				for (byte i=0;i<8;i++) {
					byte n = tmp[IND + i];
					//This loop: bits per byte
					for (byte B = 0; B < 8; B++) {
						bool bit = n & 1;
						char val = i - B;
						if (val < 0) val += 8;
						n >>= 1;
						chunk[B] |= (0 + bit) << val;
					}
				}
				//This loop: move chunk to output
				for (byte i : chunk) {
					out.push_back(i);
				}
			}
			return out;
		}
		
		
		/********!
		 * @brief
		 * 			Permutation 'C' function, which effectively will
		 * 			return a half-size byte vector
		 * 
		 * @param [in] Input
		 * 			Byte vector to permute
		 * 
		 * @returns
		 * 			Byte vector, with the length of Input, rounded up to 
		 * 			the nearest multiple of eight, then divided by two.
		 * 
		 * @details
		 * 			This function extends \c permuteB by shrinking down
		 * 			the output bytes via bit rotation, inversion, AND as
		 * 			well as XOR. After the data is permuted in B, the
		 * 			byte 0xFF will be appended if the size is odd. Once
		 * 			it is evenly divisble by two, a byte will be taken
		 * 			from the front and from the back of the permuted
		 * 			data, much like the second step of \c permuteA .
		 * 			We then perform a bit rotation and junction,
		 * 			in which the order toggles for every other byte
		 * 			pair. After that, we then apply Affine Ciphering
		 * 			to each shrunken byte, using bit-shifted versions
		 * 			of itself as multipliers and/or for adding an 
		 * 			offset, before performing <CODE>mod 256</CODE> and
		 * 			XORing the result with the original byte. This
		 * 			is an efficient way to create nonlinearity and
		 * 			reduce similarity of outputs, while upholding
		 * 			deterministic properties.
		 * 
		 * @exception std::invalid_argument
		 * 			If \c Input is empty, then there is no point in
		 * 			attempting to permute the filler bytes.
		 ********/
		inline std::vector<byte> permuteC(const std::vector<byte> &Input) {
			//! This permute function adapts 'B' and then performs XORs to shrink it down without regard to divisibility.
			std::vector<byte> Permuted = permuteB(Input);
			uint size = Permuted.size();
			if (size & 1) { //Must be divisible by 2; add 255 if it is odd
				Permuted.push_back(0xFF); size++;
			}
			std::vector<byte> outa;
			bool N = 0;
			for (uint i = 0; i < (size / 2); i++) { //PermutedB will make it divisible by 2
				byte t = Permuted[i], j = Permuted[(size / 2) - i];
				if (N) {
					outa.push_back( (t >> 4) ^ (j << 4) ^ (t & ~j) );
				} else {
					outa.push_back( (t >> 3) ^ (j << 5) ^ (~t & j) );
				}
				N = !N;
			}
			std::vector<byte> out;
			for (byte i : outa) {
				if (N) {
					out.push_back( ((i * (~i >> 4)) % 256) ^ i);
				} else {
					out.push_back( (((i * (i >> 3)) + (~i >> 5)) % 256 ) ^ i);
				}
				N = !N;
			}
			return out;
		}
		/*******!
		 * @brief
		 * 			mixes the bits from the input vector based on 
		 * 			blocks of five (so it doesn't line up with the
		 * 			permutation functions).
		 * 
		 * @param [in] Input
		 * 			Byte Vector to mix bits of.
		 * @param [in] form
		 * 			Whether or not to invert certain operations.
		 * 
		 * @returns
		 * 			mixed-bit byte vector.
		 ********/
		inline std::vector<byte> mix(const std::vector<byte> &Input, bool form) {
			//! This is necessary to move things around after permutation.
			//! Operates on blocks of 5. padding is CABEDF
			//! Form causes a cool inverse, but that's about it
			uint sz = Input.size();
			std::vector<byte> tmp = Input;
			byte Underflow = 5 - (sz % 5);
			if (Underflow > 0) {
				std::vector<byte> d = {0xCA,  0xBE, 0xDF};
				byte cnt=0, app = 0;
				while (cnt < Underflow) {
					tmp.push_back(d[app]);
					if (app == 2) app = 0; else app++;
					cnt++;
				}
				sz = tmp.size();
			}
			std::vector<byte> outa;
			for (uint c = 0; c < (sz / 5); c++) {
				byte IND = c * 5;
				std::vector<byte> chunk(5, 0);
				byte bind = 0; bool pnt = 1;
				byte last = tmp[sz - 1];
				//This loop: bytes per chunk
				for (byte i=0;i<5;i++) {
					byte n = tmp[IND + i];
					if (pnt) n ^= ~last;
					//This loop: bits per byte
					for (byte B = 0; B < 8; B++) {
						bool bit = n & 1;
						byte J = bit;
						if (pnt) {
							if (form) J = (~J << bind); else J <<= bind;
						} else {
							J <<= bind + 3; bind++;
						}
						pnt = !pnt;
						chunk[i] ^= J;
					}
					last = n;
				}
				//This loop: move chunk to output, inverting every other byte
				bool inv = 0;
				for (byte i : chunk) {
					if (inv) outa.push_back(~i); else outa.push_back(i + form);
					inv = !inv;
				}
			}
			std::vector<byte> outb;
			bool toggle = 0;
			for (uint i =0; i < sz - 1; i++) {
				byte J = (tmp[i] ^ ~outa[i]) ^ ((outa[i] << 3) | (outa[i] >> 5));
				if (toggle) {J ^= (((tmp[i] >> 2) * outa[i]) + ((tmp[i] + outa[i]) >> 3)) % 256;} //affine ciphering
				if (form) {J ^= (~outa[i] >> 3) | (outa[i] << 5);}
				toggle = !toggle;
				outb.push_back(J);
			}
			return outb;
		}
		/********!
		 * @brief
		 * 			Performs a same-size XOR and Modulo between two input
		 * 			byte vectors.
		 * 
		 * @param [in] InA
		 * 			First byte vector for intertwining.
		 * @param [in] InB
		 * 			Second byte vector for intertwining.
		 * @param [inout] _capac
		 * 			Capacity value necessary for intertwining the inputs.
		 * 
		 * @returns
		 * 			intertwine byte vector of \c _capac size.
		 * 
		 * @exception std::invalid_argument
		 * 			When either input is not \c _capac in length.
		 ********/
		inline std::vector<byte> intertwine(const std::vector<byte> &InA, const std::vector<byte> &InB, const ushort _capac) {
			if (InA.size() != _capac) throw std::invalid_argument("Input A to intertwine is not the length of the specified capacity!");
			if (InB.size() != _capac) throw std::invalid_argument("Input B to intertwine is not the length of the specified capacity!");
			std::vector<byte> temp2;
			for (ushort i = 0; i < _capac; i++) {
				byte a = InA[i], b = InB[(_capac - 1) - i];
				
				ushort ind = i + (a ^ b); while (ind >= _capac) {ind -= _capac / 2;}
				
				byte c = InA[(_capac - 1) - ind], d = InB[ind];
				
				uint J = a * b; byte N = (J + (c ^ d)) % 256;
				temp2.push_back(a ^ b ^ c ^ N ^ ~((N << 4) ^ d >> 4));
			}
			return temp2;
		}
	}
	
	//! Divides \c in into \c osize groups, padding with bytes from \c padding
	inline std::vector<std::vector<byte>> split(const std::vector<byte>& in, byte osize, std::vector<byte> padding /*= {0x11,0x22,0x33,0x44,0x55,0x66,0x77}*/) {
		std::vector<byte> tmp = in;
		std::vector<std::vector<byte>> out;
		uint tsize = tmp.size(); byte underflow = osize - (tsize % osize);
		if (underflow > 0) {
			ushort AppInd = 0, Appended = 0;
			while (Appended < underflow) {
				tmp.push_back(padding[AppInd]);
				if (AppInd == padding.size() - 1) {AppInd = 0;} else {AppInd++;}
				Appended++;
				if (Appended == underflow) break; //This may help... just trying.
			}
			tsize = tmp.size();
		}
		ushort blocks = tsize / osize;
		std::vector<byte> curb;
		for (byte i : tmp) {
			curb.push_back(i);
			if (curb.size() == blocks) {
				out.push_back(curb);
				curb.clear();
			}
		}
		return out;
	}
	
	//! Fuses a vector of byte vectors into one vector
	inline std::vector<byte> fuse(std::vector<std::vector<byte>> in) {
		std::vector<byte> tmp;
		for (std::vector<byte> i : in) {
			for (byte N : i) tmp.push_back(N);
		}
		return tmp;
	}


	//! Hash \c in , with the output capacity \c _capac , using two divisors \c _blkA and \c _blkB
	std::vector<byte> hash(const std::vector<byte>& in, const ushort _capac, const byte _blkA, const byte _blkB) {
		//! Capacity - output size, in bytes
		//! Block A  - first division size, as a denominator
		//! Block B  - second division size, as a denominator
		std::vector<std::vector<byte>> CHK = split(in, _blkB);
		std::vector<std::vector<byte>> NCHK;
		bool toggle = 0;
		for (std::vector<byte> i : CHK) {
			NCHK.push_back(low::permuteA(i));
			if (toggle) {
				NCHK.push_back(low::mix(i,1));
				NCHK.push_back(low::permuteC(i));
			}
			toggle = !toggle;
		}
		// Reset
		toggle = 1;
		NCHK.push_back(low::mix(in,1)); //insert our input
		CHK = split(fuse(NCHK), _blkA); NCHK.clear();
		for (std::vector<byte> i : CHK) {
			NCHK.push_back(low::permuteC(i));
			if (toggle) {
				NCHK.push_back(low::mix(i,0));
				NCHK.push_back(low::permuteA(low::mix(i,1)));
			}
			toggle = !toggle;
		}
		// Append Input
		toggle = 0;
		CHK = split(in, _blkB);
		for (std::vector<byte> i : CHK) {
			NCHK.push_back(low::mix(low::permuteC(i),0));
			if (toggle) NCHK.push_back(low::permuteA(low::mix(i,1)));
			toggle = !toggle;
		}
		// Reset
		toggle = 1;
		CHK = split(fuse(NCHK), _blkA); NCHK.clear();
		for (std::vector<byte> i : CHK) {
			NCHK.push_back(low::mix(low::permuteB(i),1));
			if (toggle) NCHK.push_back(low::permuteC(i));
			toggle = !toggle;
		}
		// Insert Input
		NCHK.push_back(in); 
		// Reset
		toggle = 0;
		CHK = split(fuse(NCHK), _blkB); NCHK.clear();
		for (std::vector<byte> i : CHK) {
			NCHK.push_back(low::mix(low::permuteC(i),0));
			if (toggle) NCHK.push_back(low::permuteA(i));
			toggle = !toggle;
		}
		std::vector<byte> temp = low::mix(fuse(NCHK),1); NCHK.clear();
		
		// Compress using XOR
		uint siz = temp.size(); ushort add = _capac - (siz % _capac);
		toggle = 0;
		while (add > 0) {
			temp.push_back( 0x5A );
			add--;
		}
		siz = temp.size();
		ushort ratio = (siz / _capac);
		std::vector<byte> temp2; std::vector<byte> blk(ratio, 0);
		ushort blkIn = 0; toggle = 0;
		byte lastxor = (~temp[siz - 1]) >> 3;
		for (uint i = 0; i < siz; i++) {
			if (toggle) blk[blkIn] = byte(temp[i] + lastxor); else blk[blkIn] = temp[i];
			blkIn++; toggle = !toggle;
			if (blkIn == ratio) {
				//Condense
				byte j = 0;
				for (byte A : blk) {
					j ^= A;
				}
				temp2.push_back(j);
				lastxor = byte((~j) >> 3);
				blkIn = 0;
			}
		}
		//Is now '_capac' long
		temp.clear();
		for (ushort i =0; i < _capac; i++) {
			//Semi-Affine method
			byte N = i % 256;
			byte T = ((N + lastxor) * (N + (i ^ _capac))) % 256;
			temp.push_back( T );
		}
		//intertwine with a vector of _capac length, but is just 0 - 255
		return low::intertwine(temp2, temp, _capac);
	}
}
}
