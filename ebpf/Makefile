CLANG := clang
TRACE_SRC := trace.c
TRACE_OBJ := trace.o

BPF_HEADERS := -I/usr/include

all: $(TRACE_OBJ)

$(TRACE_OBJ): $(TRACE_SRC)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
		$(BPF_HEADERS) \
		-c $(TRACE_SRC) -o $(TRACE_OBJ)

clean:
	rm -f *.o

