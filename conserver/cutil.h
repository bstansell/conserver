/*
 *  $Id: cutil.h,v 1.64 2006/01/15 17:10:14 bryan Exp $
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
#define OB_IAC		0xff	/* quote char                   */
#define OB_EXEC		'E'	/* exec a command on the client */
#define OB_GOTO		'G'	/* goto next console            */
#define OB_SUSP		'Z'	/* suspended by server          */
#define OB_ABRT		'.'	/* abort                        */

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
    FLAG errored;
    FLAG quoteiac;
    FLAG sawiac;
    FLAG sawiacsusp;
    FLAG sawiacexec;
    FLAG sawiacabrt;
    FLAG sawiacgoto;
#if HAVE_OPENSSL
    /* SSL stuff */
    SSL *ssl;
    FLAG waitForWrite;
    FLAG waitForRead;
#endif
    /* Add crypto stuff to suit */
#if DEBUG_CONSFILE_IO
    int debugrfd;
    int debugwfd;
#endif
} CONSFILE;

typedef struct item {
    char *id;
    void (*reg) PARAMS((char *));
} ITEM;

typedef struct section {
    char *id;
    void (*begin) PARAMS((char *));
    void (*end) PARAMS((void));
    void (*abort) PARAMS((void));
    void (*destroy) PARAMS((void));
    ITEM *items;
} SECTION;

typedef enum substToken {
    ISNOTHING = 0,
    ISNUMBER,
    ISSTRING
} SUBSTTOKEN;

typedef struct subst {
    SUBSTTOKEN tokens[255];
    /* data for callback function
     */
    void *data;
    /* function to retrieve a value (as a char* or int or both) for
     * a substitution
     */
    int (*callback) PARAMS((char, char **, int *));
} SUBST;

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
extern int line;		/* used by ParseFile */
extern char *file;		/* used by ParseFile */
extern SECTION sections[];	/* used by ParseFile */
extern int isMaster;

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
extern void FileSetQuoteIAC PARAMS((CONSFILE *, FLAG));
extern FLAG FileSawQuoteSusp PARAMS((CONSFILE *));
extern FLAG FileSawQuoteExec PARAMS((CONSFILE *));
extern FLAG FileSawQuoteAbrt PARAMS((CONSFILE *));
extern FLAG FileSawQuoteGoto PARAMS((CONSFILE *));
extern void Bye PARAMS((int));
extern void DestroyDataStructures PARAMS((void));
extern int IsMe PARAMS((char *));
extern char *PruneSpace PARAMS((char *));
extern int FileCanRead PARAMS((CONSFILE *, fd_set *, fd_set *));
extern int FileCanWrite PARAMS((CONSFILE *, fd_set *, fd_set *));
extern int FileBufEmpty PARAMS((CONSFILE *));
extern int SetFlags PARAMS((int, int, int));
extern char *StrDup PARAMS((char *));
extern int ParseIACBuf PARAMS((CONSFILE *, void *, int *));
extern void *MemMove PARAMS((void *, void *, size_t));
extern char *StringChar PARAMS((STRING *, int, char));
extern void ParseFile PARAMS((char *, FILE *, int));
extern void ProbeInterfaces PARAMS((in_addr_t));
extern void ProcessSubst
PARAMS((SUBST *, char **, char **, char *, char *));
#if HAVE_OPENSSL
extern SSL *FileGetSSL PARAMS((CONSFILE *));
extern void FileSetSSL PARAMS((CONSFILE *, SSL *));
extern int SSLVerifyCallback PARAMS((int, X509_STORE_CTX *));
extern int FileSSLAccept PARAMS((CONSFILE *));
extern int FileCanSSLAccept PARAMS((CONSFILE *, fd_set *, fd_set *));
#endif
