# Directories
WORK_DIR := $(shell pwd)

# General Flags
GCC := g++
CXX_OPTIMIZE_BASIC := -Ofast -fcrossjumping
CXX_OPTIMIZE_HEAVY := -O2 -fcrossjumping -faggressive-loop-optimizations -fpartial-inlining
CXX_BASIC := -std=c++17 -Wall
CXX_COMPILE := -c -fPIC $(CXX_BASIC) 
USE_INCS_FLAG := -I$(WORK_DIR)

# Library Linker Flags
LIB_MK_GEN := -shared $(CXX_BASIC) $(CXX_OPTIMIZE_BASIC)
LIB_MK_WITHNAME := -Wl,--export-dynamic,-soname=liberc-crypto.so

#0_test: liberc-crypto.so
#	$(GCC) $(USE_INCS_FLAG) -Wall $(CXX_OPTIMIZE_BASIC) -Wl,-rpath=$(WORK_DIR) -L$(WORK_DIR) 0_test.cpp -o 0_test -lerc-crypto
#	

liberc-crypto.so:
	$(GCC) $(USE_INCS_FLAG) $(CXX_COMPILE) $(CXX_OPTIMIZE_HEAVY) nacha.cpp -o nacha.o
	$(GCC) $(USE_INCS_FLAG) $(CXX_COMPILE) $(CXX_OPTIMIZE_HEAVY) viper-1.cpp -o viper-1.o
	$(GCC) $(USE_INCS_FLAG) $(CXX_COMPILE) $(CXX_OPTIMIZE_HEAVY) kobra.cpp -o kobra.o
	$(GCC) $(LIB_MK_GEN) $(LIB_MK_WITHNAME) nacha.o viper-1.o kobra.o -o liberc-crypto.so
	rm nacha.o viper-1.o kobra.o
