TARGET := cryptmon

SRC_DIR := src
BPF_OBJ := $(SRC_DIR)/$(TARGET).bpf.o
BPF_C := $(SRC_DIR)/$(TARGET).bpf.c
SKEL := $(SRC_DIR)/$(TARGET).skel.h
USER_C := $(SRC_DIR)/$(TARGET).c

INCLUDES := -I$(SRC_DIR) $(shell pkg-config --cflags libbpf libelf 2>/dev/null)
LIBS := $(shell pkg-config --libs libbpf libelf 2>/dev/null) -lz

.PHONY: all clean run log

all: $(TARGET)

$(BPF_OBJ): $(BPF_C)
		clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
					$(INCLUDES) -c $< -o $@

$(SKEL): $(BPF_OBJ)
		bpftool gen skeleton $< > $@

$(TARGET): $(USER_C) $(SKEL)
		gcc -g -O2 $(INCLUDES) $< $(LIBS) -o $@

clean:
		rm -f $(BPF_OBJ) $(SKEL) $(TARGET)

run: all
		sudo ./$(TARGET)

log:
		sudo cat /sys/kernel/debug/tracing/trace_pipe
