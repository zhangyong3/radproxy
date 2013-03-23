CC=gcc -g -O2

OBJ=cfgparse.o common.o hash.o md5.o radius.o log.o radproxy.o main.o

radproxy: $(OBJ)
	$(CC) -o $@ $^ -lpthread

%.o:%.c
	$(CC) -c $<


clean:
	rm -rf $(OBJ) radproxy
