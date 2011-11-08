CC=cc
LD=ld
CFLAGS= -g -D_REENTRANT=1 -m32
LDFLAGS= -g -shared -m32
API_INC=../../traffic/branches/buffer_upload/proxy/api/include

default: buffer_upload.so

buffer_upload.o : buffer_upload.c $(API_INC)/InkAPI.h
	$(CC) $(CFLAGS) -I$(API_INC) -o buffer_upload.o -c buffer_upload.c

buffer_upload.so: buffer_upload.o
	$(CC) $(LDFLAGS) -o buffer_upload.so buffer_upload.o

clean:
	rm -f buffer_upload.o buffer_upload.so
