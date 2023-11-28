FREEBL_CFLAGS=$(shell pkg-config --cflags nss-softokn)
FREEBL_LDFLAGS= /usr/lib64/libfreebl.a -lnssutil3 -lplds4 -lplc4 -lnspr4 -lpthread -ldl 

CMDS=time_decrypt_legacy

BUILDS=  

all: $(CMDS) $(BUILDS)

install: $(CMDS)
	cp $(CMDS) ~/bin

clean:
	rm -f $(CMDS) $(BUILDS)

time_decrypt_legacy: time_decrypt_legacy.c
	cc -o $@ -g $(FREEBL_CFLAGS) $< $(FREEBL_LDFLAGS) 

