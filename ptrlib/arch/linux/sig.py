def signal_name(code: int, detail: bool=False) -> str:
    if   code == 1:
        return 'SIGHUP'
    elif code == 2:
        return 'SIGINT' + ' (Interruption)' if detail else ''
    elif code == 3:
        return 'SIGQUIT'
    elif code == 4:
        return 'SIGILL' + ' (Illegal instruction)' if detail else ''
    elif code == 5:
        return 'SIGTRAP' + ' (int3/breakpoint)' if detail else ''
    elif code == 6:
        return 'SIGABRT'
    elif code == 7:
        return 'SIGBUS' + ' (Bus error; invalid memory access)' if detail else ''
    elif code == 8:
        return 'SIGFPE'  + ' (Floating point exception)' if detail else ''
    elif code == 9:
        return 'SIGKILL' + ' (Killed)' if detail else ''
    elif code == 10:
        return 'SIGUSR1'
    elif code == 11:
        return 'SIGSEGV' + ' (Segmentation fault)' if detail else ''
    elif code == 12:
        return 'SIGUSR2'
    elif code == 13:
        return 'SIGPIPE' + ' (Broken pipe)' if detail else ''
    elif code == 14:
        return 'SIGALRM' + ' (Timeout)' if detail else ''
    elif code == 15:
        return 'SIGTERM'
    elif code == 16:
        return 'SIGSTKFLT'
    elif code == 17:
        return 'SIGCHLD'
    elif code == 18:
        return 'SIGCONT'
    elif code == 19:
        return 'SIGSTOP'
    elif code == 20:
        return 'SIGTSTP'
    elif code == 21:
        return 'SIGTTIN'
    elif code == 22:
        return 'SIGTTOU'
    elif code == 23:
        return 'SIGURG'
    elif code == 24:
        return 'SIGXCPU'
    elif code == 25:
        return 'SIGXFSZ'
    elif code == 26:
        return 'SIGVTALRM'
    elif code == 27:
        return 'SIGPROF'
    elif code == 28:
        return 'SIGWINCH'
    elif code == 29:
        return 'SIGIO'
    elif code == 30:
        return 'SIGPWR'
    elif code == 31:
        return 'SIGSYS' + ' (Invalid system call; seccomp?)' if detail else ''
    else:
        return ''
