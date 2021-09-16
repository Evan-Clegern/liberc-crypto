/********!
 * @file liberc-crypto.hpp
 * 
 * 
 * @date
 * 		16 September 2021
 * 
 * @brief
 * 		Utility and combining header for all of the ERC-CRYPTO library.
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
 ********/


#ifndef ERCLIB_Crypto
#define ERCLIB_Crypto

#include "viper.hpp" //! the VIPER Block Cipher
#include "kobra.hpp" //! the KOBRA Calypcryptographic Algorithm
#include "nacha.hpp" //! the NACHA Hash Algorithm

//! these don't get compiled into the library; this header file is lightweight, useful definitions without "express" association
//! this file is meant to be included along with the -lerc-crypto flag.
namespace ERCLIB {
	// 'E' functions are the extended working size functions, so they'll have different outputs.
	std::vector<byte> hashData128(std::vector<byte>& input) {
		return NACHA::hash(input, 16, 5, 3);
	}
	std::vector<byte> hashData128E(std::vector<byte>& input) {
		return NACHA::hash(input, 16, 7, 4);
	}

	std::vector<byte> hashData256(std::vector<byte>& input) {
		return NACHA::hash(input, 32, 7, 4);
	}
	std::vector<byte> hashData256E(std::vector<byte>& input) {
		return NACHA::hash(input, 32, 9, 5);
	}
	
	std::vector<byte> hashData384(std::vector<byte>& input) {
		return NACHA::hash(input, 48, 9, 5);
	}
	std::vector<byte> hashData384E(std::vector<byte>& input) {
		return NACHA::hash(input, 48, 11, 6);
	}
	
	std::vector<byte> hashData512(std::vector<byte>& input) {
		return NACHA::hash(input, 64, 11, 6);
	}
	std::vector<byte> hashData512E(std::vector<byte>& input) {
		return NACHA::hash(input, 64, 13, 7);
	}
	
	std::vector<byte> hashData768(std::vector<byte>& input) {
		return NACHA::hash(input, 96, 13, 7);
	}
	std::vector<byte> hashData768E(std::vector<byte>& input) {
		return NACHA::hash(input, 96, 15, 8);
	}
	
	//! Convert a classic character string to a usable byte vector.
	const std::vector<byte> strToBVec(std::string in) {
		std::vector<byte> N;
		for (char  i : in) {
			N.push_back( byte(i) );
		}
		return N;
	}
	
	const std::string bvecToStr(const bytevec N) {
		std::string J = "";
		for (byte i : N) {
			J += char( i );
		}
		return J;
	}
}

#endif
