#include <stdio.h>
#include <stdlib.h>
#include <string.h>      /* for fgets */
#include <strings.h>     /* for bzero, bcopy */
#include <unistd.h>      /* for read, write */
#include <sys/socket.h>  /* for socket use */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <math.h>

#if defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  define SHA1 CC_SHA1
#else
#  include <openssl/md5.h>
#endif

#define HASHSTRLEN 33 /* Length of md5sum hash string */
#define MAXLINE 8192 /* max buffer length */
#define LISTENQ  1024  /* second argument to listen() */

#define RESOLVEDIPSFILE "cache/resolvedIPs.txt"
#define BLACKLISTFILE "blacklist.txt"

typedef struct {
    char md5Hash[HASHSTRLEN];
    char website[100];
    char IP[45];
    int port;
    char page[100];
} URLInfo;

typedef struct 
{
    char method[5];
    //char URL[1000];
    URLInfo urlInfo;
    char httpVersion[15];
    //bool keepConnAlive;
} Request;

int open_listenfd(int port);
void handleRequest(int connfd);
void *thread(void *vargp);

void parseFirstLine(Request* req, char *fline);
void parseRequest(Request* req, char *reqStr);

bool getIPFromCacheLookup(URLInfo *urlInfo);

bool isBlacklisted(char *website, char *ip);

void compute_md5(char *str, char hashStr[HASHSTRLEN]);

int main(int argc, char **argv)
{
    int listenfd, *connfdp, port, clientlen=sizeof(struct sockaddr_in);
    struct sockaddr_in clientaddr;
    pthread_t tid; 

    if (argc != 2) 
    {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(0);
    }
    
    port = atoi(argv[1]);

    listenfd = open_listenfd(port);
    while (1) 
    {
        connfdp = malloc(sizeof(int));
        *connfdp = accept(listenfd, (struct sockaddr*)&clientaddr, &clientlen);
        pthread_create(&tid, NULL, thread, connfdp);
    }
}

void parseURL(URLInfo* urlInfo, char *urlStr)
{
    urlInfo->port = 80;
    //compute_md5(urlStr, urlInfo->md5Hash);
    sscanf(urlStr, "http://%99[^/]/%99[^\n]", urlInfo->website, urlInfo->page);
}

/*
 * Parsing HTTP request's first line
 * "<RequestMethod> <RequestURL> <HTTPVersion*>"
 */
void parseFirstLine(Request* req, char *fline) 
{
    int i = 0;
    char *tok = strtok(fline, " \n");
    char *tokens[3];

    while (tok != NULL && i < 3) 
    {
        tokens[i++] = tok;
        tok = strtok (NULL, " \r\n");
    }

    strcpy(req->method, tokens[0]);

    parseURL(&req->urlInfo, tokens[1]);

    strcpy(req->httpVersion, tokens[2]);
}

/*
 * Splits the HTTP request string by newline
 * and fills Request struct with the parsed info
 */
void parseRequest(Request* req, char *reqStr) 
{
    int i = 0;
    char *tok = strtok(reqStr, "\n");
    char *lines[3];

    while (tok != NULL && i < 3) 
    {
        lines[i++] = tok;
        tok = strtok (NULL, "\n");
    }
    
    parseFirstLine(req, lines[0]);
    //req->keepConnAlive = strcmp(lines[2],"Connection: keep-alive\r") == 0;
}

bool getIPFromCacheLookup(URLInfo *urlInfo)
{
    bool foundIP = false;

    FILE* ips;
    char * line = NULL;
    ssize_t len = 0;
    ssize_t read;
    
    ips = fopen(RESOLVEDIPSFILE, "r");
    if (!ips)
    {
        printf("Unable to open %s\n", RESOLVEDIPSFILE);
        return false;
    }

    char website[100];
    char IP[45];
    while ((read = getline(&line, &len, ips)) != -1) 
    {
        sscanf(line, "%s    %s\n", website, IP);

        if (strcmp(website, urlInfo->website) == 0)
        {
            strcpy(urlInfo->IP, IP);
            printf("IP %s for %s found via cache lookup\n", urlInfo->IP, urlInfo->website);
            foundIP = true;
            break;
        }
        memset(website, 0, sizeof(website));
        memset(IP, 0, sizeof(IP));
    }

    fclose(ips);
    if (line)
        free(line);
    
    return foundIP;
}

bool getIPFromDNSLookup(URLInfo* urlInfo)
{
    struct hostent *host_entry;
    host_entry = gethostbyname(urlInfo->website);
    if (!host_entry)
    {
        printf("couldn't resolve %s via DNS\n", urlInfo->website);
        return false;
    }

    strcpy(urlInfo->IP, inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])));
    printf("IP %s for %s found via DNS lookup\n", urlInfo->IP, urlInfo->website);

    return true;
}

void cacheIP(URLInfo *urlInfo)
{
    FILE* ips = fopen(RESOLVEDIPSFILE, "a");
    if (!ips)
    {
        printf("Unable to open %s\n", RESOLVEDIPSFILE);
        return;
    }
    fprintf(ips, "%s    %s\n", urlInfo->website, urlInfo->IP);
    fclose(ips);
}

bool getIP(URLInfo *urlInfo) 
{
    bool resolvedIP = getIPFromCacheLookup(urlInfo);
    if (!resolvedIP)
    {
        if (getIPFromDNSLookup(urlInfo))
        {
            cacheIP(urlInfo);
            resolvedIP = true;
        }
    }
    return resolvedIP;
}

/* Checks if website or ip address is in the blacklist file */
bool isBlacklisted(char *website, char *ip)
{
    return true;
}

/*
 * Computes the md5sum hash of 'str'
 * and fills hashStr with the hash's string representation
 * Source: https://stackoverflow.com/a/7627763
 */
void compute_md5(char *str, char hashStr[HASHSTRLEN]) 
{
    unsigned char digest[CC_MD5_DIGEST_LENGTH];

    CC_MD5_CTX context;
    CC_MD5_Init(&context);
    CC_MD5_Update(&context, str, (CC_LONG)strlen(str));
    CC_MD5_Final(digest, &context);

    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; ++i)
    {
        sprintf(&hashStr[i*2], "%02x", (unsigned int)digest[i]);
    }
}

/*
 * Handles client requests
 */
void handleRequest(int connfd) 
{
    size_t n; 
    char buf[MAXLINE]; 

    n = read(connfd, buf, MAXLINE);
    printf("%s\n", buf);

    Request request;
    parseRequest(&request, buf);
    
    if (strcmp(request.method, "GET") != 0) 
    {
        printf("ONLY GET METHOD IS SUPPORTED BY PROXY!\n");
        // SEND HTTP 400 Bad Request error message
        return;
    }
    
    if (! getIP(&request.urlInfo) )
    {
        printf("Unable to get IP address for %s\n", request.urlInfo.website);
        // SEND 400 Bad Request
        return;
    }

    if (isBlacklisted(request.urlInfo.website, request.urlInfo.IP))
    {
        printf("%s | %s is blacklisted\n", request.urlInfo.website, request.urlInfo.IP);
        // SEND ERROR 403 Forbidden
        return;
    }
}

/* thread routine */
void * thread(void * vargp) 
{  
    int connfd = *((int *)vargp);
    pthread_detach(pthread_self()); 
    free(vargp);
    handleRequest(connfd);
    close(connfd);
    return NULL;
}

/* 
 * open_listenfd - open and return a listening socket on port
 * Returns -1 in case of failure 
 */
int open_listenfd(int port) 
{
    int listenfd, optval=1;
    struct sockaddr_in serveraddr;
  
    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, 
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;

    /* listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET; 
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    serveraddr.sin_port = htons((unsigned short)port); 
    if (bind(listenfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
        return -1;
    return listenfd;
} /* end open_listenfd */