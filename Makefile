CC		:= gcc
CFLAGS	:= -Wall -Wno-unused-function -std=c11
LFLAGS	:=
OBJECTS := build/utils.o build/tcp.o

all: server client

server: build/server.o $(OBJECTS)
	@echo ' Linking  $@'
	@$(CC) $(LFLAGS) $^ -o $@

client: build/client.o $(OBJECTS)
	@echo ' Linking  $@'
	@$(CC) $(LFLAGS) $^ -o $@

build/%.o: src/%.c build-dir
	@echo 'Compiling $<'
	@$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean build-dir
clean:
	@rm -f server client $(OBJECTS)
	@rmdir build
	
build-dir:
	@mkdir -p build
