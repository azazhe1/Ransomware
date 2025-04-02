NAME := azazhel_ransomware
INC_DIR := include
MAIN := bin/ransomware
SRC_C := $(wildcard src/*.c)
SERVER_IP ?= 127.0.0.1
CURL_VERSION := 8.12.1
CURL_TARBALL := curl-$(CURL_VERSION).tar.xz
CURL_DIR := curl-$(CURL_VERSION)
CURL_LIB := $(CURL_DIR)/lib/.libs/libcurl.a
CFLAGS := $(CURL_LIB) -Og -g -Wall -Wextra -I$(INC_DIR) -lcrypto -static -DSERVER_IP=\"$(SERVER_IP)\"
CC := gcc

all: $(MAIN)

$(CURL_LIB):
	wget -q https://curl.se/download/$(CURL_TARBALL) -O $(CURL_TARBALL)
	tar xvf $(CURL_TARBALL)
	cd $(CURL_DIR) && CC=$(CC) ./configure --disable-shared --enable-static --prefix=/tmp/curl --disable-ldap --disable-sspi --without-librtmp --disable-ftp --disable-file --disable-dict --disable-telnet --disable-tftp --disable-rtsp --disable-pop3 --disable-imap --disable-smtp --disable-gopher --disable-smb --without-libidn --without-ssl --without-nghttp2 --disable-mqtt --without-zlib --without-brotli --without-zstd --without-libpsl --without-libidn2 --disable-docs
	$(MAKE) -C $(CURL_DIR) && $(MAKE) -C $(CURL_DIR) install

$(MAIN): $(SRC_C) $(CURL_LIB)
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm -f $(MAIN) src/*~ src/*.swap
	rm -rf $(CURL_DIR) $(CURL_TARBALL)
