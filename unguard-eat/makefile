MAKEFLAGS += "-s -j 16"

##
## Project Name
##
NAME := "unguard-eat"

##
## Compilers and linkers
##
CC_X64 := x86_64-w64-mingw32
CC_X86 := i686-w64-mingw32

##
## build time keys
##
KN_HASH := $(shell python3 -c "import random; print(hex(random.getrandbits(32)))")

##
## source code
##
PIC_SRC := $(wildcard src/*.cc)
PIC_OBJ := $(PIC_SRC:%.cc=%.o)

##
## Compiler flags
##
PIC_CFLAGS := -Os -fno-asynchronous-unwind-tables -nostdlib
PIC_CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1
PIC_CFLAGS += -s -ffunction-sections -falign-jumps=1 -w
PIC_CFLAGS += -falign-labels=1 -fPIC -Wl,-Tscripts/sections.ld
PIC_CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup
PIC_CFLAGS += -Iinclude -masm=intel -fpermissive -mrdrnd
PIC_CFLAGS += -D KAINE_OBF_KEY_HASH=$(KN_HASH) -I../headers

all: x64

x64: x64-asm $(PIC_OBJ)
	@ $(CC_X64)-g++ bin/obj/*.x64.o -o bin/$(NAME).x64.exe $(PIC_CFLAGS)
	@ python3 scripts/extract.py -f bin/$(NAME).x64.exe -o bin/$(NAME).x64.bin

x64-asm:
	@ nasm -f win64 asm/x64/Common.asm -o bin/obj/asm_Common.x64.o

$(PIC_OBJ):
	@ echo compiling $(basename $@).cc ==> bin/obj/$(NAME)_$(basename $(notdir $@)).x64.o
	@ $(CC_X64)-g++ -o bin/obj/$(NAME)_$(basename $(notdir $@)).x64.o -c $(basename $@).cc $(PIC_CFLAGS)

clean:
	@ rm -rf bin/obj/*.o*