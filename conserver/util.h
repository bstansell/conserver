/*
 *  $Id: util.h,v 1.13 2002-01-21 02:48:33-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

/* Struct to wrap information about a "file"...
 * This can be a socket, local file, whatever.  We do this so
 * we can add encryption to sockets (and generalize I/O).
 */
enum consFileType {
    simpleFile,
    simpleSocket,
#ifdef TLS_SUPPORT
    TLSSocket,
#endif
};

typedef struct dynamicString {
    char *string;
    int used;
    int allocated;
} STRING;

typedef struct consFile {
    /* Standard socket type stuff */
    enum consFileType ftype;
    int fd;
#ifdef TLS_SUPPORT
    /* TLS/SSL stuff */
    SSL_CTX *ctx;
    SSL *sslfd;
    BIO *sbio;
    int ctx_connections;
#endif
    /* Add crypto stuff to suit */
} CONSFILE;

extern void Debug();
extern void Error();
extern void Info();
extern int outputPid, fDebug;
extern char *progname;
extern int thepid;
extern void simpleSignal();
extern int maxfiles();
extern void FmtCtlStr();
extern CONSFILE *fileOpenFD();
extern CONSFILE *fileOpen();
extern int fileClose();
extern int fileRead();
extern int fileWrite();
extern int fileStat();
extern int fileSeek();
extern int fileSend();
extern int fileFDNum();
extern void OutOfMem();
extern char *buildString();
extern char *buildMyString();
extern char *buildMyStringChar();
extern char *readLine();
