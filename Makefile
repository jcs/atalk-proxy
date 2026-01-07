CFLAGS	= -O2 -Wall -Wunused -Wmissing-prototypes -Wstrict-prototypes -Wunused
CFLAGS += -g
CC	= cc

LIBS	= -lpcap

PROG	= atalk-proxy
OBJS	= atalk-proxy.o

all: $(PROG)

clean:
	rm -f $(PROG) $(OBJS)

$(PROG): $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $@

$(OBJS): *.c
	$(CC) $(CFLAGS) -c atalk-proxy.c -o $@
