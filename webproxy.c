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

#define HASHSTRLEN 33

// Source: https://stackoverflow.com/a/7627763
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

int main(int argc, char **argv)
{
    char stringHash[HASHSTRLEN];
    const char* string = "http://www.yahoo.com/logo.jpg";

    compute_md5(string, stringHash);

    printf("%s\n", stringHash);

    return 0;
}

