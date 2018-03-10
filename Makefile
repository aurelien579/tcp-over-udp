CC		:= gcc
CFLAGS	:= -Wall -Wno-unused-function -std=c11
LFLAGS	:=
OBJECTS := utils.o tcp.o

all: server client

server: server.o $(OBJECTS)
	@echo ' Linking  $@'
	@$(CC) $(LFLAGS) $^ -o $@

client: client.o $(OBJECTS)
	@echo ' Linking  $@'
	@$(CC) $(LFLAGS) $^ -o $@

%.o: %.c
	@echo 'Compiling $<'
	@$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	@rm -f server client *.o
