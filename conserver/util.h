/*
 *  $Id: util.h,v 1.41 2003-03-08 08:39:57-08 bryan Exp $
 *
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#if PROTOTYPES
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
    struct dynamicString *next;
    struct dynamicString *prev;
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

extern int isMultiProc, fDebug, fVerbose;
extern char *progname;
extern pid_t thepid;

extern const char *StrTime PARAMS((time_t *));
extern void Debug PARAMS((int, char *, ...));
extern void Error PARAMS((char *, ...));
extern void Msg PARAMS((char *, ...));
extern void Verbose PARAMS((char *, ...));
extern void SimpleSignal PARAMS((int, RETSIGTYPE(*)(int)));
extern int GetMaxFiles PARAMS(());
extern char *FmtCtl PARAMS((int, STRING *));
extern void FmtCtlStr PARAMS((char *, int, STRING *));
extern CONSFILE *FileOpenFD PARAMS((int, enum consFileType));
extern CONSFILE *FileOpen PARAMS((const char *, int, int));
extern int FileClose PARAMS((CONSFILE **));
extern int FileRead PARAMS((CONSFILE *, void *, int));
extern int FileWrite PARAMS((CONSFILE *, const char *, int));
extern void FileVWrite PARAMS((CONSFILE *, const char *, va_list));
extern void FilePrint PARAMS((CONSFILE *, const char *, ...));
extern int FileStat PARAMS((CONSFILE *, struct stat *));
extern int FileSeek PARAMS((CONSFILE *, off_t, int));
extern int FileSend PARAMS((CONSFILE *, const void *, size_t, int));
extern int FileFDNum PARAMS((CONSFILE *));
extern int FileUnopen PARAMS((CONSFILE *));
extern void OutOfMem PARAMS(());
extern char *BuildTmpString PARAMS((const char *));
extern char *BuildTmpStringChar PARAMS((const char));
extern char *BuildString PARAMS((const char *, STRING *));
extern char *BuildStringChar PARAMS((const char, STRING *));
extern void InitString PARAMS((STRING *));
extern void DestroyString PARAMS((STRING *));
extern void DestroyStrings PARAMS((void));
extern STRING *AllocString PARAMS((void));
extern char *ReadLine PARAMS((FILE *, STRING *, int *));
extern enum consFileType FileGetType PARAMS((CONSFILE *));
extern void FileSetType PARAMS((CONSFILE *, enum consFileType));
extern void Bye PARAMS((int));
extern void DestroyDataStructures PARAMS((void));
#if HAVE_OPENSSL
extern SSL *FileGetSSL PARAMS((CONSFILE *));
extern void FileSetSSL PARAMS((CONSFILE *, SSL *));
extern int SSLVerifyCallback PARAMS((int, X509_STORE_CTX *));
#endif
