CCFLAGS=-DNOIPV6 -g -O2
LDFLAGS=
CC=gcc

OBJ=cfgparse.o common.o hash.o md5.o radius.o log.o radproxy.o main.o dlist.o

radproxy: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ -lpthread

%.o:%.c
	$(CC) $(CCFLAGS) -c $<


clean:
	rm -rf $(OBJ) radproxy
