//============================================================================
// Name        : SSLClient.c
// Compiling   : gcc -c -o SSLClient.o SSLClient.c
//               gcc -o SSLClient SSLClient.o -lssl -lcrypto
//============================================================================
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <libgen.h>
#define MAX_MESSAGE_LENGTH 5000

SSL *ssl;
int sock;
FILE *file;
SSL_CTX *ctx;





void dwnld_HTTP(char message[], char filename[], int socket_desc);
void dwnld_HTTPS(char message[], char filename[], int socket_desc);
    
    
int main(int argc, char *argv[])
{

    if(argc != 2){
        printf("command line argument not proper\n");
        return 0;
    }

    char *site = argv[1];
    int count = 0, i = (site[4]=='s'?8:7);
    for(; site[i+count] != '/'; count++);
    
    char host[count+1], path[strlen(site)-i-count+10];
    for(int j = 0; j < count; j++)
        host[j] = site[i+j];
    host[count] = '\0';
    
    i += count, count = 0;
    for(int j = 0; site[i+count]; count++, j++)
        path[j] = site[i+count];
    
    path[count] = '\0';
    
    count = 0;
    i = strlen(site)-1;
    for(; site[i-count] != '/'; count++);

    char filename[count+1];
    for(int j = 1; j <= count; j++)
        filename[j-1] = site[i-count+j];
    filename[count] = '\0';

    // extracted the host, filename , path

    char message[4096];

    sprintf(message, "GET %s%s%s%s", path, " HTTP/1.1\r\nHost: ", host, "\r\nConnection: Close\r\n\r\n");

    char *server_ip_addr;
 

 
    int server_port=(site[4]=='s'?443:80); 






    int s;
    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); // socket creation
    if (s < 0) {
        printf("Error creating socket.\n");
        return -1;
    }

    // retrive server_ip_addr from hostname
    struct hostent *he;
    he = gethostbyname(host);
    if (he == NULL)
    {
        herror("gethostbyname");
        exit(1);
    }

    struct sockaddr_in sa;
    memset (&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr = *((struct in_addr *)he->h_addr);
    sa.sin_port        = htons (server_port); 
    socklen_t socklen = sizeof(sa);

    if (connect(s, (struct sockaddr *)&sa, socklen)) {
        printf("Error connecting to server.\n");
        return -1;
    }

 

    remove(filename);
    file = fopen(filename, "ab");

    if (file == NULL)
    {
        printf("File could not opened");
    }


    if(server_port==80){
       dwnld_HTTP(message,filename,s); 
    }
    else{
        dwnld_HTTPS(message,filename,s);
    }

    close(s);
    shutdown(s, 0);
    shutdown(s, 1);
    shutdown(s, 2);
    return 0;
}

void dwnld_HTTP(char message[], char filename[], int socket_desc){
    
    char receive_msg[100010] = {0};

    if( send(socket_desc , message , strlen(message) , 0) < 0){
        puts("Send failed");
        exit(1);
    }

    remove(filename); // deletes existing file
    FILE *f = fopen(filename, "ab");
    if(f == NULL){
        printf("Error while opening file.\n");
        exit(1);
    }

    int count = 0;
    if((count = recv(socket_desc, receive_msg, 100000, 0)) > 0){
        if(receive_msg[9] != '2' || receive_msg[10] != '0' || receive_msg[11] != '0'){
            printf("Didn't got a 200 OK response. Following is header received. Exiting Bye!!.\n\n");
            printf("%s", receive_msg);
            remove(filename);
            exit(1);
        }
        
        int i = 4;
        while(receive_msg[i-4] != '\r' || receive_msg[i-3] != '\n' || receive_msg[i-2] != '\r' || receive_msg[i-1] != '\n')
            i++;

        fwrite(receive_msg+i , count-i , 1, f);
        receive_msg[i] = '\0';
        printf("HTTP response header:\n\n%s", receive_msg);
    }
    
    while((count = recv(socket_desc, receive_msg, 100000, 0)) > 0){
        fwrite(receive_msg , count , 1, f);
    }

    printf("reply received.\n");
    fclose(f);
    
}





void dwnld_HTTPS(char message[], char filename[], int socket_desc){

    SSL* ssl;
    SSL_CTX* ctx;

    char receive_msg[100010] = {0};

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL){
        printf("ctx is null.\n");
        exit(1);
    }
    ssl = SSL_new (ctx);
    if(!ssl){
        printf("Error creating ssl.\n");
        exit(1);
    }

    SSL_set_fd(ssl, socket_desc);

    if(SSL_connect(ssl) <= 0){
        printf("Error while creating ssl connection.\n");
        exit(1);
    }
    printf("SSL connected.\n");


    if(SSL_write(ssl, message, strlen(message)) <= 0){
        puts("Send failed");
        exit(1);
    }

    remove(filename); // deletes existing file
    FILE *f = fopen(filename, "ab");
    if(f == NULL){
        printf("Error while opening file.\n");
        exit(1);
    }

    int count = 0;
    if((count = SSL_read(ssl, receive_msg, 100000)) > 0){
        if(receive_msg[9] != '2' || receive_msg[10] != '0' || receive_msg[11] != '0'){
            printf("Didn't got a 200 OK response. Following is header received. Exiting Bye!!.\n\n");
            printf("%s", receive_msg);
            remove(filename);
            exit(1);
        }
        int i = 4;
        while(receive_msg[i-4] != '\r' || receive_msg[i-3] != '\n' || receive_msg[i-2] != '\r' || receive_msg[i-1] != '\n')
            i++;

        fwrite(receive_msg+i , count-i , 1, f);
        receive_msg[i] = '\0';
        printf("HTTP response header:\n\n%s", receive_msg);
    }

    while((count = SSL_read(ssl, receive_msg, 100000)) > 0){
        fwrite(receive_msg , count , 1, f);
    }
    
    printf("reply received.\n");
    fclose(f);
    SSL_CTX_free(ctx);
}
