/*
 *  $Id: cutil.h,v 1.56 2003/11/10 20:38:25 bryan Exp $
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
    simplePipe,
#if HAVE_OPENSSL
    SSLSocket,
#endif
    nothing
};

typedef enum IOState {
    ISDISCONNECTED = 0,
    INCONNECT,
    ISNORMAL,
#if HAVE_OPENSSL
    INSSLACCEPT,
    INSSLSHUTDOWN,
#endif
    ISFLUSHING
} IOSTATE;

typedef enum flag {
    FLAGUNKNOWN = 0,
    FLAGTRUE,
    FLAGFALSE
} FLAG;


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
    int fdout;			/* only used when a simplePipe */
    STRING *wbuf;
#if HAVE_OPENSSL
    /* SSL stuff */
    SSL *ssl;
    FLAG waitForWrite;
    FLAG waitForRead;
#endif
    /* Add crypto stuff to suit */
} CONSFILE;

extern int isMultiProc, fDebug, fVerbose, fErrorPrinted;
extern char *progname;
extern pid_t thepid;
#define MAXHOSTNAME 1024
extern char myHostname[];
extern struct in_addr *myAddrs;
extern fd_set rinit;
extern fd_set winit;
extern int maxfd;
extern int debugLineNo;
extern char *debugFileName;

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
extern CONSFILE *FileOpenPipe PARAMS((int, int));
extern CONSFILE *FileOpen PARAMS((const char *, int, int));
extern int FileClose PARAMS((CONSFILE **));
extern int FileRead PARAMS((CONSFILE *, void *, int));
extern int FileWrite PARAMS((CONSFILE *, FLAG, char *, int));
extern void FileVWrite PARAMS((CONSFILE *, FLAG, char *, va_list));
extern void FilePrint PARAMS((CONSFILE *, FLAG, char *, ...));
extern int FileStat PARAMS((CONSFILE *, struct stat *));
extern int FileSeek PARAMS((CONSFILE *, off_t, int));
extern int FileSend PARAMS((CONSFILE *, const void *, size_t, int));
extern int FileFDNum PARAMS((CONSFILE *));
extern int FileFDOutNum PARAMS((CONSFILE *));
extern int FileUnopen PARAMS((CONSFILE *));
extern void OutOfMem PARAMS(());
extern char *BuildTmpString PARAMS((const char *));
extern char *BuildTmpStringChar PARAMS((const char));
extern char *BuildTmpStringPrint PARAMS((char *, ...));
extern char *BuildString PARAMS((const char *, STRING *));
extern char *BuildStringChar PARAMS((const char, STRING *));
extern char *BuildStringPrint PARAMS((STRING *, char *, ...));
extern char *BuildStringN PARAMS((const char *, int, STRING *));
extern char *ShiftString PARAMS((STRING *, int));
extern void InitString PARAMS((STRING *));
extern void DestroyString PARAMS((STRING *));
extern void DestroyStrings PARAMS((void));
extern STRING *AllocString PARAMS((void));
extern char *ReadLine PARAMS((FILE *, STRING *, int *));
extern enum consFileType FileGetType PARAMS((CONSFILE *));
extern void FileSetType PARAMS((CONSFILE *, enum consFileType));
extern void Bye PARAMS((int));
extern void DestroyDataStructures PARAMS((void));
extern int IsMe PARAMS((char *));
extern char *PruneSpace PARAMS((char *));
extern int FileCanRead PARAMS((CONSFILE *, fd_set *, fd_set *));
extern int FileCanWrite PARAMS((CONSFILE *, fd_set *, fd_set *));
extern int FileBufEmpty PARAMS((CONSFILE *));
extern int SetFlags PARAMS((int, int, int));
extern char *StrDup PARAMS((char *));
#if HAVE_OPENSSL
extern SSL *FileGetSSL PARAMS((CONSFILE *));
extern void FileSetSSL PARAMS((CONSFILE *, SSL *));
extern int SSLVerifyCallback PARAMS((int, X509_STORE_CTX *));
extern int FileSSLAccept PARAMS((CONSFILE *));
extern int FileCanSSLAccept PARAMS((CONSFILE *, fd_set *, fd_set *));
#endif
