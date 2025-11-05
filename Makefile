CC = gcc
CFLAGS = -Wall -Wextra -O2

TARGET = chacha20

all: $(TARGET) run

$(TARGET): chacha20.c
	$(CC) $(CFLAGS) -o $(TARGET) chacha20.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
