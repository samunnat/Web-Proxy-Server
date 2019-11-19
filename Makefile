# build an executable named server from server.c
all: webproxy.c 
	gcc webproxy.c -o webproxy

clean: 
	$(RM) webproxy
