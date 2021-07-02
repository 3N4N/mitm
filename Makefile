CC     = gcc
CFLAGS = -g -w -Iinc/
LIBS   =

SRCS   = $(wildcard src/*.c)
OBJS   = $(patsubst src/%.c,bin/%.o,$(SRCS))
DEPS   = $(OBJS:.o:=.d)
DIRS   = src inc bin
EXE    = a.out

all: $(DIRS) $(EXE) relay

$(DIRS):
	mkdir -p $@

$(EXE): $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

relay: ./relay.c
	$(CC) -o relay relay.c $(LIBS)

bin/%.o : src/%.c
	$(CC) -o $@ $(CFLAGS) -c $<

bin/%.o : src/%.c inc/%.h
	$(CC) -o $@ $(CFLAGS) -c $<

run : all
	./$(EXE)

clean:
	rm -rf bin *~ $(EXE)
