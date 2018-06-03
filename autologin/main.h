/*
 * parse options
 */

extern char *progname, *au_terse[4], *u_help[9];
#ifndef u_terse
# define u_terse	(au_terse[0])
#endif
extern int main();
extern int fMakeUtmp, iErrs;
extern char *pcCommand, *pcGroup, *pcLogin, *pcTty;
extern int Process(void);
/* from std_help.m */
/* from std_version.m */
/* from autologin.m */
