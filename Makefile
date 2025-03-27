NAME := azazhel_ransomware
INC_DIR := include
MAIN := bin/ransomware
SRC_C := $(wildcard src/*.c)
CFLAGS := -Og -g -Wall -Wextra -I$(INC_DIR) -lcrypto -lcurl

$(MAIN): $(SRC_C)
	gcc $^ -o $@ $(CFLAGS)

clean:
	rm -f $(MAIN) src/*~ src/*.swap