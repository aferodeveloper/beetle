TARGET = beetle
LIBS = -lbluetooth
CC = gcc
CFLAGS = -g -Wall
INSTALL_PATH?=/usr

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)

install:
	-/usr/bin/install -s --mode=755 beetle $(INSTALL_PATH)/bin/
	-/usr/bin/install --mode=444 beetle.1 $(INSTALL_PATH)/share/man/man1/
