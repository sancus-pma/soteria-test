# Makefile

ROM       = 48K
RAM       = 10K
STACK     = 256
VENDOR_ID = 1234
NODE_KEY  = deadbeefcafebabedeadbeefcafebabe

OBJS      = sm_loader.o ctest.o other.o main.o aes.o uart.o xtime.o
CFLAGS    = -Wall -Werror 


all: main.elf


main.elf: main-no-crypt.elf
	sancus-crypt --verbose --key `sancus-hmac --vendor-key $(VENDOR_ID) --key $(NODE_KEY)` -o main.elf main-no-crypt.elf

main-no-crypt.elf: main-no-mac.elf
	sancus-hmac --key `sancus-hmac --vendor-key $(VENDOR_ID) --key $(NODE_KEY)` -o main-no-crypt.elf main-no-mac.elf

main-no-mac.elf: $(OBJS)
	sancus-ld --standalone --rom-size $(ROM) --ram-size $(RAM) --sm-stack-size $(STACK) -o main-no-mac.elf $(OBJS)

xtime.o: xtime.c
	msp430-gcc -D__MSP430F149__ $(CFLAGS) -Os -c -o $@ $<

%.o: %.c
	LD_LIBRARY_PATH=/usr/local/lib sancus-cc $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS)
	rm -f main-no-mac.elf main-no-crypt.elf

distclean: clean
	rm -f main.elf

 
.PHONY : all run clean distclean
