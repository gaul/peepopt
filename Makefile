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

clean:
	rm -f \
		peepopt \
		peepopt_test \
		*.o
