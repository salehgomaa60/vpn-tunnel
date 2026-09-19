CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -Wpedantic -std=c99 -D_GNU_SOURCE -O2
DEBUG_FLAGS = -g3 -O0 -DDEBUG -Wall -Wextra -Werror -Wpedantic -std=c99 -D_GNU_SOURCE
ASAN_FLAGS = -g3 -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Werror -Wpedantic -std=c99 -D_GNU_SOURCE

SODIUM_INC ?= -Ideps/dist/include
SODIUM_LIB ?= -Ldeps/dist/lib -lsodium -lpthread

INCLUDES = -Isrc $(SODIUM_INC)
LIBS = $(SODIUM_LIB)

SRCS = $(wildcard src/*.c)
CORE_SRCS = $(filter-out src/main.c, $(SRCS))
CORE_OBJS = $(CORE_SRCS:.c=.o)
OBJS = $(SRCS:.c=.o)

TEST_SRCS = $(wildcard tests/*.c)
TEST_BINS = $(TEST_SRCS:.c=)

# LibFuzzer harnesses (require clang on Linux)
FUZZ_CC    = clang
FUZZ_FLAGS = -g -O1 -fsanitize=address,undefined,fuzzer -std=c99 -D_GNU_SOURCE
FUZZ_BINS  = fuzz/fuzz_packet_parser fuzz/fuzz_aead fuzz/fuzz_handshake fuzz/fuzz_replay

.PHONY: all test clean debug asan fuzz fuzz-clean

all: vpn-tunnel $(TEST_BINS)

vpn-tunnel: src/main.o $(CORE_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

tests/test_%: tests/test_%.c $(CORE_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(CORE_OBJS) -o $@ $(LIBS)

test: all
	@echo "=== Running Test Suite ==="
	@for t in $(TEST_BINS); do \
		echo "Executing $$t..."; \
		$$t || exit 1; \
	done
	@echo "=== All Tests Passed Successfully ==="

debug: CFLAGS = $(DEBUG_FLAGS)
debug: clean all

asan: CFLAGS = $(ASAN_FLAGS)
asan: clean all

# ---------------------------------------------------------------------------
# Fuzz targets (Linux + clang only)
# Builds all LibFuzzer harnesses against ASan + UBSan + LibFuzzer.
# Requires: clang with libFuzzer support (standard on clang >= 6)
# ---------------------------------------------------------------------------
fuzz: $(FUZZ_BINS)

# Build fuzz object files separately with clang + fuzzer flags
fuzz/%.o: src/%.c
	$(FUZZ_CC) $(FUZZ_FLAGS) $(INCLUDES) -c $< -o $@

# Packet parser harness: only needs packet + logging + config objects
fuzz/fuzz_packet_parser: fuzz/fuzz_packet_parser.c \
		$(patsubst src/%.c,fuzz/%.o,$(filter src/packet.c src/logging.c src/config.c, $(SRCS)))
	$(FUZZ_CC) $(FUZZ_FLAGS) $(INCLUDES) $^ $(LIBS) -o $@

# AEAD harness: needs crypto + logging + config
fuzz/fuzz_aead: fuzz/fuzz_aead.c \
		$(patsubst src/%.c,fuzz/%.o,$(filter src/crypto.c src/logging.c src/config.c, $(SRCS)))
	$(FUZZ_CC) $(FUZZ_FLAGS) $(INCLUDES) $^ $(LIBS) -o $@

# Handshake harness: needs everything
fuzz/fuzz_handshake: fuzz/fuzz_handshake.c \
		$(patsubst src/%.c,fuzz/%.o,$(SRCS))
	$(FUZZ_CC) $(FUZZ_FLAGS) $(INCLUDES) $^ $(LIBS) -o $@

# Replay harness: only needs replay + logging
fuzz/fuzz_replay: fuzz/fuzz_replay.c \
		$(patsubst src/%.c,fuzz/%.o,$(filter src/replay.c src/logging.c, $(SRCS)))
	$(FUZZ_CC) $(FUZZ_FLAGS) $(INCLUDES) $^ $(LIBS) -o $@

fuzz-clean:
	rm -f fuzz/*.o $(FUZZ_BINS)

clean:
	rm -f src/*.o tests/*.o $(TEST_BINS) vpn-tunnel
