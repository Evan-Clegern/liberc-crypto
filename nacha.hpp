#ifndef erclib_nacha_included
#define erclib_nacha_included

#include <vector>
#include <stdexcept>
#include <string>

typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned int uint;

namespace ERCLIB {
namespace NACHA {
	namespace low {
		extern inline std::vector<byte> permuteA(const std::vector<byte> &Input);
		extern inline std::vector<byte> permuteB(const std::vector<byte> &Input);
		extern inline std::vector<byte> permuteC(const std::vector<byte> &Input);
		extern inline std::vector<byte> mix(const std::vector<byte> &Input, bool form);
		extern std::vector<byte> intertwine(const std::vector<byte> &InA, const std::vector<byte> &InB, const ushort _capac);
	}
	extern inline std::vector<std::vector<byte>> split(const std::vector<byte>& in, byte osize, std::vector<byte> padding = {0x11,0x22,0x33,0x44,0x55,0x66,0x77});
	extern inline std::vector<byte> fuse(std::vector<std::vector<byte>> in);
	extern std::vector<byte> hash(const std::vector<byte>& in, const ushort _capac, const byte _blkA, const byte _blkB);
}
}

#endif
