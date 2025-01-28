/*
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 */

#include <stdarg.h>
#if HAVE_OPENSSL
# include <openssl/ssl.h>
# include <openssl/bn.h>
# include <openssl/dh.h>
# include <openssl/err.h>
# if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define TLS_method SSLv23_method
# endif/* OPENSSL_VERSION_NUMBER < 0x10100000L */
# if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
#  define CIPHER_SEC0
# else
#  define CIPHER_SEC0 ":@SECLEVEL=0"
# endif/* OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER) */
#endif
#if HAVE_GSSAPI
# include <gssapi/gssapi.h>
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
#if HAVE_GSSAPI
    INGSSACCEPT,
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
    void (*reg)(char *);
} ITEM;

typedef struct section {
    char *id;
    void (*begin)(char *);
    void (*end)(void);
    void (*abort)(void);
    void (*destroy)(void);
    ITEM *items;
} SECTION;

typedef enum substToken {
    ISNOTHING = 0,
    ISNUMBER,
    ISSTRING
} SUBSTTOKEN;

typedef struct subst {
    /* function to retrieve a token type based on a character
     */
    SUBSTTOKEN (*token)(char);
    /* data for callback function
     */
    void *data;
    /* function to retrieve a value (as a char* or int or both) for
     * a substitution
     */
    int (*value)(char, char **, int *);
} SUBST;

extern int isMultiProc, fDebug, fVerbose, fErrorPrinted;
extern char *progname;
extern pid_t thepid;
#define MAXHOSTNAME 1024
extern char myHostname[];
#if !USE_IPV6
extern struct in_addr *myAddrs;
#endif
extern fd_set rinit;
extern fd_set winit;
extern int maxfd;
extern int debugLineNo;
extern char *debugFileName;
extern int line;		/* used by ParseFile */
extern char *file;		/* used by ParseFile */
extern SECTION sections[];	/* used by ParseFile */
extern int isMaster;

extern const char *StrTime(time_t *);
extern void Debug(int, char *, ...);
extern void Error(char *, ...);
extern void Msg(char *, ...);
extern void Verbose(char *, ...);
extern void SimpleSignal(int, void(*)(int));
extern int GetMaxFiles();
extern char *FmtCtl(int, STRING *);
extern void FmtCtlStr(char *, int, STRING *);
extern CONSFILE *FileOpenFD(int, enum consFileType);
extern CONSFILE *FileOpenPipe(int, int);
extern CONSFILE *FileOpen(const char *, int, int);
extern int FileClose(CONSFILE **);
extern int FileRead(CONSFILE *, void *, int);
extern int FileWrite(CONSFILE *, FLAG, char *, int);
extern void FileVWrite(CONSFILE *, FLAG, char *, va_list);
extern void FilePrint(CONSFILE *, FLAG, char *, ...);
extern int FileStat(CONSFILE *, struct stat *);
extern int FileSeek(CONSFILE *, off_t, int);
extern int FileSend(CONSFILE *, const void *, size_t, int);
extern int FileFDNum(CONSFILE *);
extern int FileFDOutNum(CONSFILE *);
extern int FileUnopen(CONSFILE *);
extern void OutOfMem();
extern char *BuildTmpString(const char *);
extern char *BuildTmpStringChar(const char);
extern char *BuildTmpStringPrint(char *, ...);
extern char *BuildString(const char *, STRING *);
extern char *BuildStringChar(const char, STRING *);
extern char *BuildStringPrint(STRING *, char *, ...);
extern char *BuildStringN(const char *, int, STRING *);
extern char *ShiftString(STRING *, int);
extern void InitString(STRING *);
extern void DestroyString(STRING *);
extern void DestroyStrings(void);
extern STRING *AllocString(void);
extern char *ReadLine(FILE *, STRING *, int *);
extern enum consFileType FileGetType(CONSFILE *);
extern void FileSetType(CONSFILE *, enum consFileType);
extern void FileSetQuoteIAC(CONSFILE *, FLAG);
extern FLAG FileSawQuoteSusp(CONSFILE *);
extern FLAG FileSawQuoteExec(CONSFILE *);
extern FLAG FileSawQuoteAbrt(CONSFILE *);
extern FLAG FileSawQuoteGoto(CONSFILE *);
extern void Bye(int);
extern void DestroyDataStructures(void);
extern int IsMe(char *);
extern char *PruneSpace(char *);
extern int FileCanRead(CONSFILE *, fd_set *, fd_set *);
extern int FileCanWrite(CONSFILE *, fd_set *, fd_set *);
extern int FileBufEmpty(CONSFILE *);
extern int SetFlags(int, int, int);
extern char *StrDup(const char *);
extern int ParseIACBuf(CONSFILE *, void *, int *);
extern void *MemMove(void *, void *, size_t);
extern char *StringChar(STRING *, int, char);
extern void ParseFile(char *, FILE *, int);
#if !USE_IPV6
extern void ProbeInterfaces(in_addr_t);
#endif
extern void ProcessSubst(SUBST *, char **, char **, char *, char *);
extern char *MyVersion(void);
extern unsigned int AtoU(char *);
extern void StrCpy(char *, const char *, unsigned int);
extern void Sleep(useconds_t);
#if HAVE_OPENSSL
extern SSL *FileGetSSL(CONSFILE *);
extern void FileSetSSL(CONSFILE *, SSL *);
extern int SSLVerifyCallback(int, X509_STORE_CTX *);
extern int FileSSLAccept(CONSFILE *);
extern int FileCanSSLAccept(CONSFILE *, fd_set *, fd_set *);
#endif
