NAME=gash
DIR=$(shell pwd)

export PATH := $(PATH):bin

all: gash_binary gash_doc

gash_binary:
	g++ source/gash.cpp \
	source/Hashes/adler32.cpp \
	source/Hashes/crc32.cpp \
	source/Hashes/elf.cpp \
	source/Hashes/md5.cpp \
	source/Hashes/sha256.cpp \
	source/Hashes/hash_abstract.cpp \
	-o bin/gash

gash_doc:

dist:
	tar -czvf $(NAME).tar.gz .
