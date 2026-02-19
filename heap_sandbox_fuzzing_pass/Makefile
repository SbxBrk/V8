BASE = /usr
CC = $(BASE)/bin/clang
CXX = $(BASE)/bin/clang++
AR = $(BASE)/bin/llvm-ar

CFLAGS      ?= -O3 -funroll-loops -g -Wall -Wno-pointer-sign
CXXFLAGS    ?= -O3 -funroll-loops -g -Wall

# Used for llvm pass compilation
LLVM_CONFIG ?= $(BASE)/bin/llvm-config
CLANG_CFL    = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS)
CLANG_LFL    = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

TARGETS = heap_sandbox_fuzzing_pass.so

all: $(TARGETS)

clean:
	-rm -f $(TARGETS)
	-find -iname "*.o" -exec rm -v {} \;

heap_sandbox_fuzzing_pass.so: heap_sandbox_fuzzing_pass.cc
	$(CXX) $(CLANG_CFL) -fPIC -shared $^ -o $@ $(CLANG_LFL)
