/*
 *  $Id: util.h,v 1.22 2002-02-25 14:00:38-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#if USE_ANSI_PROTO
#include <stdarg.h>
#else
#include <varargs.h>
#endif

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

extern int outputPid, fDebug;
extern char *progname;
extern int thepid;

#if USE_ANSI_PROTO
extern void Debug(int, char *, ...);
extern void Error(char *, ...);
extern void Info(char *, ...);
extern void simpleSignal(int, RETSIGTYPE(*)(int));
extern int cmaxfiles();
extern void FmtCtlStr(char *, STRING *);
extern CONSFILE *fileOpenFD(int, enum consFileType);
extern CONSFILE *fileOpen(const char *, int, int);
extern int fileClose(CONSFILE **);
extern int fileRead(CONSFILE *, void *, int);
extern int fileWrite(CONSFILE *, const char *, int);
extern void fileVwrite(CONSFILE *, const char *, va_list);
extern void filePrint(CONSFILE *, const char *, ...);
extern int fileStat(CONSFILE *, struct stat *);
extern int fileSeek(CONSFILE *, off_t, int);
extern int fileSend(CONSFILE *, const void *, size_t, int);
extern int fileFDNum(CONSFILE *);
extern void OutOfMem();
extern char *buildString(const char *);
extern char *buildStringChar(const char);
extern char *buildMyString(const char *, STRING *);
extern char *buildMyStringChar(const char, STRING *);
extern void initString(STRING *);
extern void destroyString(STRING *);
extern char *readLine(FILE *, STRING *, int *);
#else
extern void Debug();
extern void Error();
extern void Info();
extern void simpleSignal();
extern int cmaxfiles();
extern void FmtCtlStr();
extern CONSFILE *fileOpenFD();
extern CONSFILE *fileOpen();
extern int fileClose();
extern int fileRead();
extern int fileWrite();
extern void fileVWrite();
extern void filePrint();
extern int fileStat();
extern int fileSeek();
extern int fileSend();
extern int fileFDNum();
extern void OutOfMem();
extern char *buildString();
extern char *buildStringChar();
extern char *buildMyString();
extern char *buildMyStringChar();
extern void initString();
extern void destroyString();
extern char *readLine();
#endif
