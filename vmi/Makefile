TARGETS = io_vmi.so
CFLAGS = -fPIC
LDFLAGS = -shared


all: $(TARGETS)

%.so: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $^ -o $@

clean:
	rm -f $(TARGETS)
