# build an executable named server from server.c
all: webproxy.c 
	gcc webproxy.c -o webproxy -g

clean: 
	$(RM) webproxy
	$(RM) -r webproxy.DSYM
	$(RM) resolvedIPs.txt
	$(RM) cache/*
