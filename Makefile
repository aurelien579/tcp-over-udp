CC		:= gcc
CFLAGS	:= -Wall -Wno-unused-function -std=c11
LFLAGS	:=
OBJECTS := build/utils.o build/tcp.o
TERM	:= gnome-terminal

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

.PHONY: clean build-dir run
clean:
	@rm -f server client
	@rm -R build
	
build-dir:
	@mkdir -p build

run: client server
	gnome-terminal -- bash -c "echo Server\ :; ./server 4545; exec bash"
	gnome-terminal -- bash -c "echo Client\ :; ./client 127.0.0.1 4545; exec bash"
