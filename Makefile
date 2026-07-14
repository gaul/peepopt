ifndef XED_PATH
$(error "must provide XED_PATH")
endif

CFLAGS = -O1 -g -Wall

%.o: %.c
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install/include/ -c $< -o $@

peepopt: main.o peepopt.o
	$(CC) $(CFLAGS) peepopt.o main.o ${XED_PATH}/obj/libxed.a -o peepopt

peepopt_test: peepopt.o peepopt_test.o
	$(CC) $(CFLAGS) peepopt.o peepopt_test.o ${XED_PATH}/obj/libxed.a -o peepopt_test

all: peepopt peepopt_test

test: peepopt_test
	./peepopt_test

test-apx-fixture: test-apx-fixture.S test-apx-driver.c
	$(CC) $(CFLAGS) -O0 -o $@ test-apx-fixture.S test-apx-driver.c

# Runs the rewritten fixture under Intel SDE's APX emulation; requires
# SDE_PATH (and optionally SDE_CHIP, default -dmr).
test-apx: peepopt test-apx-fixture
	@test -n "$(SDE_PATH)" || { echo "must provide SDE_PATH" >&2; exit 1; }
	SDE_PATH="$(SDE_PATH)" SDE_CHIP="$(SDE_CHIP)" ./test-apx.sh

clean:
	rm -f \
		peepopt \
		peepopt_test \
		test-apx-fixture \
		test-apx-fixture.opt \
		apx-*.out \
		apx-*.log \
		*.o
