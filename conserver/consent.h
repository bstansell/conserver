/*
 *  Copyright conserver.com, 2000
 *
 *  Maintainer/Enhancer: Bryan Stansell (bryan@conserver.com)
 *
 *  Copyright GNAC, Inc., 1998
 */

/*
 * Copyright 1992 Purdue Research Foundation, West Lafayette, Indiana
 * 47907.  All rights reserved.
 *
 * Written by Kevin S Braunsdorf, ksb@cc.purdue.edu, purdue!ksb
 *
 * This software is not subject to any license of the American Telephone
 * and Telegraph Company or the Regents of the University of California.
 *
 * Permission is granted to anyone to use this software for any purpose on
 * any computer system, and to alter it and redistribute it freely, subject
 * to the following restrictions:
 *
 * 1. Neither the authors nor Purdue University are responsible for any
 *    consequences of the use of this software.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Credit to the authors and Purdue
 *    University must appear in documentation and sources.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 *
 * 4. This notice may not be removed or altered.
 */
/*
 * Network console modifications by Robert Olson, olson@mcs.anl.gov.
 */


/* stuff to keep track of a console entry
 */
typedef struct baud {		/* a baud rate table                    */
    char acrate[8];
    int irate;
} BAUD;

typedef struct parity {		/* a parity bits table                  */
    char *key;
    int iset;
    int iclr;
} PARITY;

typedef enum consType {
    UNKNOWNTYPE = 0,
    DEVICE,
    EXEC,
    HOST,
    NOOP,
    UDS,
#if HAVE_FREEIPMI
    IPMI,
#endif
} CONSTYPE;

#if HAVE_FREEIPMI
# define IPMIL_UNKNOWN  (0)
# define IPMIL_USER     (IPMICONSOLE_PRIVILEGE_USER+1)
# define IPMIL_OPERATOR (IPMICONSOLE_PRIVILEGE_OPERATOR+1)
# define IPMIL_ADMIN    (IPMICONSOLE_PRIVILEGE_ADMIN+1)
#endif

typedef struct names {
    char *name;
    struct names *next;
} NAMES;

typedef struct consentUsers {
    NAMES *user;
    short not;
    struct consentUsers *next;
} CONSENTUSERS;

/* we calloc() these things, so we're trying to make everything be
 * "empty" when it's got a zero value
 */
typedef struct consent {	/* console information                  */
    /*** config file settings ***/
    char *server;		/* server name                          */
    CONSTYPE type;		/* console type                         */
    NAMES *aliases;		/* aliases for server name              */
    /* type == DEVICE */
    char *device;		/* device file                          */
    char *devicesubst;		/* device substitution pattern          */
    BAUD *baud;			/* the baud on this console port        */
    PARITY *parity;		/* the parity on this line              */
    FLAG hupcl;			/* use HUPCL                            */
    FLAG cstopb;		/* use two stop bits                    */
    FLAG ixon;			/* XON/XOFF flow control on output      */
    FLAG ixany;			/* any character to restart output      */
    FLAG ixoff;			/* XON/XOFF flow control on input       */
#if defined(CRTSCTS)
    FLAG crtscts;		/* use hardware flow control            */
#endif
#if HAVE_FREEIPMI
    /* type == IPMI */
    int ipmiprivlevel;		/* IPMI authentication level            */
    ipmiconsole_ctx_t ipmictx;	/* IPMI ctx                             */
    unsigned int ipmiworkaround;	/* IPMI workaround flags                */
    short ipmiwrkset;		/* workaround flags set in config       */
    int ipmiciphersuite;	/* IPMI cipher suite                    */
    char *username;		/* Username to log as                   */
    char *password;		/* Login Password                       */
    STRING *ipmikg;		/* IPMI k_g auth key                    */
#endif
    /* type == HOST */
    char *host;			/* hostname                             */
    unsigned short netport;	/* final port    | netport = portbase + */
    unsigned short port;	/* port number   |      portinc * port  */
    unsigned short portbase;	/* port base                            */
    unsigned short portinc;	/* port increment                       */
    FLAG raw;			/* raw or telnet protocol?              */
    /* type == EXEC */
    char *exec;			/* exec command                         */
    char *execsubst;		/* exec substitution pattern            */
    uid_t execuid;		/* user to run exec as                  */
    gid_t execgid;		/* group to run exec as                 */
    /* type == UDS */
    char *uds;			/* socket file                          */
    char *udssubst;		/* socket file substitution pattern     */
    /* global stuff */
    char *master;		/* master hostname                      */
    unsigned short breakNum;	/* break type [1-35]                    */
    char *logfile;		/* logfile                              */
    off_t logfilemax;		/* size limit for rolling logfile       */
    char *initcmd;		/* initcmd command                      */
    char *initsubst;		/* initcmd substitution pattern         */
    uid_t inituid;		/* user to run initcmd as               */
    gid_t initgid;		/* group to run initcmd as              */
    char *motd;			/* motd                                 */
    time_t idletimeout;		/* idle timeout                         */
    char *idlestring;		/* string to print when idle            */
    unsigned short spinmax;	/* initialization spin maximum          */
    unsigned short spintimer;	/* initialization spin timer            */
    char *replstring;		/* generic string for replacements      */
    char *tasklist;		/* list of valid tasks                  */
    char *breaklist;		/* list of valid break sequences        */
    /* timestamp stuff */
    int mark;			/* Mark (chime) interval                */
    long nextMark;		/* Next mark (chime) time               */
    FLAG activitylog;		/* log attach/detach/bump               */
    FLAG breaklog;		/* log breaks sent                      */
    FLAG tasklog;		/* log tasks invoked                    */
    /* options */
    FLAG ondemand;		/* bring up on-demand                   */
    FLAG reinitoncc;		/* open if down on client connect       */
    FLAG striphigh;		/* strip high-bit of console data       */
    FLAG autoreinit;		/* auto-reinitialize if failed          */
    FLAG unloved;		/* copy "unloved" data to stdout        */
    FLAG login;			/* allow logins to the console          */

    /*** runtime settings ***/
    CONSFILE *fdlog;		/* the local log file                   */
    CONSFILE *cofile;		/* the port to talk to machine on       */
    char *execSlave;		/* pseudo-device slave side             */
    int execSlaveFD;		/* fd of slave side                     */
    pid_t ipid;			/* pid of virtual command               */
    pid_t initpid;		/* pid of initcmd command               */
    CONSFILE *initfile;		/* the command run on init              */
    pid_t taskpid;		/* pid of task running                  */
    CONSFILE *taskfile;		/* the output from the task (read-only) */
    STRING *wbuf;		/* write() buffer                       */
    int wbufIAC;		/* next IAC location in wbuf            */
    IOSTATE ioState;		/* state of the socket                  */
    time_t stateTimer;		/* timer for ioState states             */
    time_t lastWrite;		/* time of last data sent to console    */
    size_t totalWrites;		/* bytes wrote to console log		*/
#if HAVE_GETTIMEOFDAY
    struct timeval lastInit;	/* time of last initialization          */
#else
    time_t lastInit;		/* time of last initialization          */
#endif
    unsigned int connectCount;	/* number of times init has happen	*/
    unsigned short spincount;	/* initialization spin counter          */

    /*** state information ***/
    char acline[132 * 2 + 2];	/* max chars we will call a line        */
    int iend;			/* length of data stored in acline      */
    int telnetState;		/* state for telnet negotiations        */
    FLAG sentDoEcho;		/* have we sent telnet DO ECHO cmd?     */
    FLAG sentDoSGA;		/* have we sent telnet DO SGA cmd?      */
    unsigned short autoReUp;	/* is it coming back up automatically?  */
    FLAG downHard;		/* did it go down unexpectedly?         */
    unsigned short nolog;	/* don't log output                     */
    unsigned short fup;		/* we setup this line?                  */
    unsigned short fronly;	/* we can only read this console        */

    /*** list management ***/
    struct client *pCLon;	/* clients on this console              */
    struct client *pCLwr;	/* client that is writting on console   */
    CONSENTUSERS *rw;		/* rw users                             */
    CONSENTUSERS *ro;		/* ro users                             */
    struct consent *pCEnext;	/* next console entry                   */
} CONSENT;

typedef struct remote {		/* console at another host              */
    struct remote *pRCnext;	/* next remote console we know about    */
    struct remote *pRCuniq;	/* list of uniq remote servers          */
    char *rserver;		/* remote server name                   */
    char *rhost;		/* remote host to call to get it        */
    NAMES *aliases;		/* aliases for remote server name       */
} REMOTE;

extern PARITY *FindParity(char *);
extern BAUD *FindBaud(char *);
extern void ConsInit(CONSENT *);
extern void ConsDown(CONSENT *, FLAG, FLAG);
extern REMOTE *FindUniq(REMOTE *);
extern void DestroyRemoteConsole(REMOTE *);
extern void StartInit(CONSENT *);
extern void StopInit(CONSENT *);
extern char *ConsState(CONSENT *);
extern void SetupTty(CONSENT *, int);
