CC = gcc
CFLAGS = -Wall $(shell pkg-config fuse --cflags)
LDFLAGS = $(shell pkg-config fuse --libs) -lz

TARGET = concatfs
SRC = src/concatfs.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
