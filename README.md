# Web Proxy Server

The proxy sits between HTTP clients and HTTP servers. The client sends a HTTP request to the proxy. The proxy then forwards this request to the server, and receives the reply. The proxy will send the reply back to the client while also caching it for a certain amount of time for future requests.

## How To Use:
1. make
2. ./webproxy <port> <cacheTimeoutInSeconds>
3. Configure a web-browser to use the HTTP web-proxy
4. Go to an HTTP website like http://netsys.cs.colorado.edu/

### How It Works
1. Web proxy listens for incoming connections on socket;
2. Each incoming request is assigned a thread that'll be running the handleRequest function.
3. In handleRequest, the client's request is loaded onto a buffer, which is then parsed out into a Request struct object.
4. The request is checked for a valid method (only GET supported), valid website (IP address cached in resolvedIPs.txt), and blacklist status. HTTP Error responses are sent out if the request fails any of these checks.
5. The cache directory is searched for a file with the filename md5sum(request.URL).
6. If that cache file is found, the timestamp of when it was last updated (found in the first line) is checked against the cache-timeout-value. If the cache file isn't stale, all the contents of the file past the first line is sent to the client.
7. If the cache file isn't found, or it's stale, a socket connection to the webserver of the request is made. A copy of the client's HTTP request is forwarded to the webserver, and the response is both sent to the client, and cached.

### Notes
The most relevant sections of the code are in the handleRequest, respondByCache, and respondByServer methods. Everything else is mostly helper methods.

### Author: Sam Lamichhane