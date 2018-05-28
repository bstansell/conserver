# mkcmd parser for autologin program
%%
%%

integer variable "iErrs" {
	init "0"
}

char* 'c' {
        named "pcCommand"
	param "cmd"
        init '(char *)0'
        help "command to run"
}

function 'e' {
        named "putenv"
	param "env=value"
	update "if (%n(%N) != 0) { (void) fprintf(stderr, \"%%s: putenv(\\\"%%s\\\"): failed\\n\", %b, %N);exit(1);}"
        help "environment variable to set"
}

char* 'g' {
        named "pcGroup"
	param "group"
        init '(char *)0'
        help "initial group"
}

char* 'l' {
        named "pcLogin"
	param "login"
        init '(char *)0'
        help "login name"
}

char* 't' {
        named "pcTty"
	param "tty"
        init '(char *)0'
        help "attach to this terminal"
}

boolean 'u' {
        named "fMakeUtmp"
        init "1"
        update "%run = 0;"
        help "do no make utmp entry"
}

exit {
        named "Process"
        update "%n();"
        aborts "exit(iErrs);"
}
