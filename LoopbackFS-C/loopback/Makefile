# Makefile for macFUSE loopback filesystem

CC = clang
CFLAGS = -Wall -Wextra -I/usr/local/include -D_FILE_OFFSET_BITS=64
LDFLAGS = -L/usr/local/lib -lfuse

TARGET = loopback
SOURCE = loopback.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
	-umount test_mount 2>/dev/null || true
	-rmdir test_mount 2>/dev/null || true
	-rmdir test_source 2>/dev/null || true

# Test setup
test_setup:
	mkdir -p test_source test_mount
	echo "Hello from test source!" > test_source/test.txt
	echo "Another file" > test_source/file2.txt

# Run filesystem in debug mode (use Ctrl+C to stop)
test_run: $(TARGET) test_setup
	./$(TARGET) test_mount -f -d

# Test in another terminal while filesystem is running
test_check:
	ls -la test_mount/
	echo "Testing file access:"
	cat test_mount/$(shell pwd)/test_source/test.txt || echo "File not found"

# Cleanup
test_clean:
	-umount test_mount 2>/dev/null || true
	-rmdir test_mount 2>/dev/null || true
	-rmdir test_source 2>/dev/null || true

help:
	@echo "Available targets:"
	@echo "  all        - Build the loopback filesystem"
	@echo "  clean      - Remove built files"
	@echo "  test_setup - Create test directories and files"
	@echo "  test_run   - Run filesystem in debug mode"
	@echo "  test_check - Test filesystem access (run in another terminal)"
	@echo "  test_clean - Clean up test files and unmount"
	@echo "  help       - Show this help"