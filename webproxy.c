#include <arpa/inet.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>      /* for fgets */
#include <strings.h>     /* for bzero, bcopy */
#include <sys/socket.h>  /* for socket use */
#include <time.h>
#include <unistd.h>      /* for read, write */

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

#define BLACKLISTFILE "blacklist.txt"

int cacheTimeoutInSeconds = 3600;
#define CACHEDIR "cache/"
#define RESOLVEDIPSFILE "resolvedIPs.txt"

typedef enum
{ 
    SUCCESS, 
    BADREQUEST, 
    IPNOTFOUND, 
    BLACKLISTED,
    PAGENOTFOUND
} PROXYSTATUS;

typedef struct 
{
    char md5Hash[HASHSTRLEN];
    char website[100];
    char IP[45];
    int port;
    char page[200];
} URLInfo;

typedef struct 
{
    char method[10];
    URLInfo urlInfo;
    char httpVersion[15];
    //bool keepConnAlive;
} Request;

int open_listenfd(int port);
void *thread(void *vargp);

void handleRequest(int connfd);
bool respondByCache(int clientSock, char *clientBuffer, Request* request);
bool respondByServer(int clientSock, char *serverBuffer, Request* request);

int main(int argc, char **argv)
{
    int listenfd, *connfdp, port, timeout;
    socklen_t clientlen = sizeof(struct sockaddr_in);
    struct sockaddr_in clientaddr;
    pthread_t tid; 

    if (argc < 3) 
    {
        fprintf(stderr, "usage: %s <port> <cacheTimeout(seconds)>\n", argv[0]);
        exit(0);
    }
    
    port = atoi(argv[1]);
    cacheTimeoutInSeconds = atoi(argv[2]);

    listenfd = open_listenfd(port);
    while (1) 
    {
        connfdp = malloc(sizeof(int));
        *connfdp = accept(listenfd, (struct sockaddr*)&clientaddr, &clientlen);
        pthread_create(&tid, NULL, thread, connfdp);
    }
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

void parseURL(URLInfo* urlInfo, char *urlStr)
{
    urlInfo->port = 80;
    compute_md5(urlStr, urlInfo->md5Hash);
    sscanf(urlStr, "http://%99[^/]/%99[^\n]", urlInfo->website, urlInfo->page);
}

/*
 * Parsing HTTP request's first line
 * "<RequestMethod> <RequestURL> <HTTPVersion*>"
 */
bool parseFirstLine(Request* req, char *fline) 
{
    int i = 0;
    char *tok = strtok(fline, " \n");
    char *tokens[3];

    while (tok != NULL && i < 3) 
    {
        tokens[i++] = tok;
        tok = strtok (NULL, " \r\n");
    }

    if (i < 3)
    {
        printf("Invalid First Line\n");
        return false;   
    } 

    strcpy(req->httpVersion, tokens[2]);
    
    strcpy(req->method, tokens[0]);
    if (strcmp(req->method, "GET") != 0)
    {
        //printf("Unsupported method %s\n", req->method);
        return false;
    }

    parseURL(&req->urlInfo, tokens[1]);
    return true;
}

/*
 * Splits the HTTP request string by newline
 * and fills Request struct with the parsed info
 */
bool parseRequest(Request* req, char *reqStr) 
{
    int i = 0;
    int linesToParse = 1;   // increase if need to parse more details

    char *tok = strtok(reqStr, "\n");
    char *lines[linesToParse];

    while (tok != NULL && i < linesToParse) 
    {
        lines[i++] = tok;
        tok = strtok (NULL, "\n");
    }

    if (i < linesToParse)
        return false;
    
    return parseFirstLine(req, lines[0]);;
}

bool getIPFromCacheLookup(URLInfo *urlInfo)
{
    bool foundIP = false;

    FILE* ips;
    char * line = NULL;
    size_t len = 0;
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
            //printf("IP %s for %s found via cache lookup\n", urlInfo->IP, urlInfo->website);
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
    //printf("IP %s for %s found via DNS lookup\n", urlInfo->IP, urlInfo->website);
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
        else
        {
            printf("Couldn't get IP for %s\n", urlInfo->website);
        }
    }
    return resolvedIP;
}

/* Checks if website or ip address is in the blacklist file */
bool isBlacklisted(char *website, char *ip)
{
    FILE* blackListFile = fopen(BLACKLISTFILE, "r");
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, blackListFile)) != -1) 
    {
        if (strstr(line, website) != NULL)
        {
            printf("'%s' is blacklisted\n", website);
            return true;
        }
        else if(strstr(line, ip) != NULL)
        {
            printf("'%s' is blacklisted\n", ip);
            return true;
        }
    }
    
    fclose(blackListFile);
    if (line)
        free(line);
    
    return false;
}

void sendError(PROXYSTATUS errReason, char *clientBuffer, char *httpVersion, int clientSock)
{
    if (errReason == BADREQUEST)
    {
        snprintf(clientBuffer, MAXLINE, "<html><body><h1>%s 400 Bad Request</h1></body></html>", httpVersion);
    }
    else if (errReason == IPNOTFOUND)
    {
        snprintf(clientBuffer, MAXLINE, "<html><body><h1>%s 404 Not Found</h1></body></html>", httpVersion);
    }
    else if (errReason == BLACKLISTED)
    {
        snprintf(clientBuffer, MAXLINE, "<html><body><h1>%s 403 Forbidden</h1></body></html>", httpVersion);
    }
    else if (errReason == PAGENOTFOUND)
    {
        snprintf(clientBuffer, MAXLINE, "<html><body><h1>%s 404 Not Found</h1></body></html>", httpVersion);
    }
    send(clientSock, clientBuffer, strlen(clientBuffer), 0);
}

/*
 * Handles client requests
 */
void handleRequest(int clientSock) 
{
    char clientBuffer[MAXLINE];
    char serverBuffer[MAXLINE];
    size_t n; 

    n = read(clientSock, clientBuffer, MAXLINE);
    strcpy(serverBuffer, clientBuffer);

    //printf("%s\n", serverBuffer);
    Request request;

    if (! parseRequest(&request, clientBuffer))
    {
        sendError(BADREQUEST, clientBuffer, request.httpVersion, clientSock);
        return;
    }
    
    if (! getIP(&request.urlInfo) )
    {
        sendError(IPNOTFOUND, clientBuffer, request.httpVersion, clientSock);
        return;
    }

    if (isBlacklisted(request.urlInfo.website, request.urlInfo.IP))
    {
        sendError(BLACKLISTED, clientBuffer, request.httpVersion, clientSock);
        return;
    }

    bzero(clientBuffer, MAXLINE);

    //printf("trying to get %s\n", request.urlInfo.page);
    bool respondSuccess = respondByCache(clientSock, clientBuffer, &request) || respondByServer(clientSock, serverBuffer, &request);
    if (!respondSuccess)
    {
        bzero(clientBuffer, MAXLINE);
        sendError(PAGENOTFOUND, clientBuffer, request.httpVersion, clientSock);
    }
    //printf("Resolved %s\n", request.urlInfo.page);
}

bool isCacheFileValid(FILE *cacheFile, char *cacheFileName, int *bytesRead)
{
    if (!cacheFile)
    {   
        //printf("%s not in cache\n", cacheFileName);
        return false;
    }
    char firstLine[30];    
    if (feof(cacheFile) || (!fgets(firstLine, sizeof(firstLine), cacheFile)))
    {
        //printf("couldn't read first line of cache file\n");
        fclose(cacheFile);
        return false;
    }
    *bytesRead = (int)ftell(cacheFile);
    
    int cacheTimeStamp;
    if (sscanf(firstLine, "%d\n", &cacheTimeStamp) <= 0)
    {
        printf("couldn't parse first line of cache file\n");
        fclose(cacheFile);
        return false;
    }
    
    int now = (unsigned)time(NULL);
    int cacheFileAge = now - cacheTimeStamp;
    if (cacheFileAge >= cacheTimeoutInSeconds)
    {
        printf("Cache file %s is stale (Age: %d, Timeout %d)\n", cacheFileName, cacheFileAge, cacheTimeoutInSeconds);
        fclose(cacheFile);
        return false;
    }
    return true;
}

long int getFileSize(FILE* file) 
{
    fseek(file, 0L, SEEK_END);
    long int fileSize = ftell(file);
    fseek(file, 0L, SEEK_SET);
    return fileSize;
}

bool respondByCache(int clientSock, char *clientBuffer, Request* request)
{
    FILE* cacheFile;
    int bytesRead;

    char cacheFileName[strlen(CACHEDIR)+HASHSTRLEN];
    strcpy(cacheFileName, CACHEDIR);
    strcat(cacheFileName, request->urlInfo.md5Hash);

    cacheFile = fopen(cacheFileName, "rb");
    if(!isCacheFileValid(cacheFile, cacheFileName, &bytesRead))
    {
        return false;
    }
    
    int bytesToBeRead = getFileSize(cacheFile) - bytesRead;
    fseek(cacheFile, bytesRead, SEEK_SET);

    int readBufferSize = fmin(MAXLINE, bytesToBeRead);

    while ( (bytesRead = fread(clientBuffer, 1, readBufferSize, cacheFile)) > 0 )
    {
        write(clientSock, clientBuffer, bytesRead);
        bytesToBeRead -= bytesRead;

        readBufferSize = fmin(MAXLINE, bytesToBeRead);
        bzero(clientBuffer, MAXLINE);
    }

    fclose(cacheFile);

    printf("got %s by cache\n", request->urlInfo.md5Hash);
    return true;
}

bool connectToServer(int *serverSock, struct sockaddr_in *server, socklen_t *serverLen, char *IP)
{
    *serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (*serverSock == -1)
    {
        printf("Failed to create server socket");
        return false;
    }

    server->sin_family = AF_INET;
    inet_aton(IP, &server->sin_addr);
    server->sin_port = htons(80);
    
    *serverLen = sizeof(*server);
    int conn = connect(*serverSock, (struct sockaddr *) server, *serverLen);
    if (conn == -1)
    {
        printf("error in socket conection\n");
        return false;
    }
    
    return true;
}

void writeTimeStamp(FILE *file)
{
    fprintf(file, "%d\n", (unsigned)time(NULL));
}

bool respondByServer(int clientSock, char *serverBuffer, Request* request)
{
    int serverSock;
    struct sockaddr_in server;
    socklen_t serverLen;
    if (!connectToServer(&serverSock, &server, &serverLen, request->urlInfo.IP))
    {
        return false;
    }
    
    ssize_t sent_bytes;
    ssize_t received_bytes;
    
    sent_bytes = send(serverSock, serverBuffer, strlen(serverBuffer), 0);
    bzero(serverBuffer, MAXLINE);

    char cacheFileName[strlen(CACHEDIR)+HASHSTRLEN];
    strcpy(cacheFileName, CACHEDIR);
    strcat(cacheFileName, request->urlInfo.md5Hash);
    FILE* cacheFile = fopen(cacheFileName, "wb+");
    
    writeTimeStamp(cacheFile);
    
    while ((received_bytes = recvfrom(serverSock, serverBuffer, MAXLINE, 0, (struct sockaddr *) &server, &serverLen)) > 0) 
    {
        sent_bytes = send(clientSock, serverBuffer, received_bytes, 0);
        
        fwrite(serverBuffer, 1, received_bytes, cacheFile);

        bzero(serverBuffer, MAXLINE);
    }

    fclose(cacheFile);
    close(serverSock);

    printf("got %s by server\n", request->urlInfo.md5Hash);
    return true;
}

/* thread routine */
void * thread(void * vargp) 
{  
    int clientSock = *((int *)vargp);
    pthread_detach(pthread_self()); 
    free(vargp);
    handleRequest(clientSock);
    close(clientSock);
    return NULL;
}

/* 
 * open_listenfd - open and return a listening socket on port
 * Returns -1 in case of failure 
 */
int open_listenfd(int port) 
{
    int listenfd, optval=1;
    struct sockaddr_in proxyaddr;
  
    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, 
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;

    /* listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    bzero((char *) &proxyaddr, sizeof(proxyaddr));
    proxyaddr.sin_family = AF_INET; 
    proxyaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    proxyaddr.sin_port = htons((unsigned short)port); 
    if (bind(listenfd, (struct sockaddr*)&proxyaddr, sizeof(proxyaddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
        return -1;
    return listenfd;
} /* end open_listenfd */