# Cross-compile test_vtable.cpp to Windows exe with debug info
# Requires: clang, lld, mingw-w64 headers/libs

CC = clang++
TARGET = test_vtable.exe
PDB = test_vtable.pdb
SRC = test_vtable.cpp

# Cross-compile to Windows x86_64 with both DWARF and CodeView/PDB debug info
CFLAGS = --target=x86_64-w64-mingw32 \
         -gdwarf -gcodeview \
         -fuse-ld=lld \
         -Wl,--pdb=$(PDB) \
         -static

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) $(PDB)

.PHONY: all clean
