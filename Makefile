CC=clang
CFLAGS=-Wall -g -Iinclude -I/opt/homebrew/opt/capstone/include
LDFLAGS=-L/opt/homebrew/opt/capstone/lib -lcapstone

SRC=src/main.c src/fuzz.c src/crash.c src/disasm.c src/rop.c src/format.c src/inputgen.c src/coverage.c

all: fuzzpro

fuzzpro: $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f fuzzpro *.o
