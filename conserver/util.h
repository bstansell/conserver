/*
 *  $Id: util.h,v 1.32 2002-10-01 20:52:02-07 bryan Exp $
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
#if HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/* communication constants
 */
#define OB_SUSP		'Z'	/* suspended by server          */
#define OB_DROP		'.'	/* dropped by server            */

/* Struct to wrap information about a "file"...
 * This can be a socket, local file, whatever.  We do this so
 * we can add encryption to sockets (and generalize I/O).
 */
enum consFileType {
    simpleFile,
    simpleSocket,
#if HAVE_OPENSSL
    SSLSocket,
#endif
    nothing
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
#if HAVE_OPENSSL
    /* SSL stuff */
    SSL *ssl;
    int waitonWrite;
    int waitonRead;
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
extern void FmtCtlStr(char *, int, STRING *);
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
extern enum consFileType fileGetType(CONSFILE *);
extern void fileSetType(CONSFILE *, enum consFileType);
#if HAVE_OPENSSL
extern SSL *fileGetSSL(CONSFILE *);
extern void fileSetSSL(CONSFILE *, SSL *);
extern int ssl_verify_callback(int, X509_STORE_CTX *);
#endif
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
extern enum consFileType fileGetType();
extern void fileSetType();
#if HAVE_OPENSSL
extern SSL *fileGetSSL();
extern void fileSetSSL();
extern int ssl_verify_callback();
#endif
#endif
