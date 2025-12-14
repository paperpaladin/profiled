CFLAGS = -std=c11 -g -O1 -Wall -Wextra -ffile-prefix-map=$(CURDIR)=.

all: profiled

profiled: profiled.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	@./t/run.sh

clean:
	rm -f profiled

.PHONY: all test clean
