OUTPUT ?= beacon
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./headers $(EXTRA_CFLAGS)
LDFLAGS = -lssl -lcrypto -lcurl -lpthread

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
TARGET = $(BIN_DIR)/$(OUTPUT)

SOURCES = \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/beacon.c \
	$(SRC_DIR)/parse.c \
	$(SRC_DIR)/settings.c \
	$(SRC_DIR)/security.c \
	$(SRC_DIR)/metadata.c \
	$(SRC_DIR)/channel_http.c \
	$(SRC_DIR)/proto.c \
	$(SRC_DIR)/profile.c \
	$(SRC_DIR)/encoders.c \
	$(SRC_DIR)/files.c \
	$(SRC_DIR)/pivot.c

OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

.PHONY: all clean debug directories test_profile

all: directories $(TARGET)

directories:
	@mkdir -p $(BIN_DIR) $(OBJ_DIR)

$(TARGET): $(OBJECTS)
	@echo "[LD] $@"
	@$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "[+] built $@"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

debug: CFLAGS += -g -DDEBUG
debug: clean all

# Host-side unit test for apply/recover (no curl/network)
test_profile: directories
	@$(CC) $(CFLAGS) -DPROFILE_SELFTEST \
		$(SRC_DIR)/profile.c $(SRC_DIR)/encoders.c $(SRC_DIR)/parse.c \
		-o $(BIN_DIR)/test_profile -lssl -lcrypto
	@echo "[+] built $(BIN_DIR)/test_profile — run on Linux target"
