## macOS/2024.SpectralBlur.DPRK/SpectralBlur-macshare [🛑 HIGH]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| HIGH | [anti-static/macho/footer]() | [higher-entropy machO trailer (normally NULL) - possible viral infection](https://www.virusbulletin.com/virusbulletin/2013/06/multiplatform-madness) | [_PAGEZERO](https://github.com/search?q=_PAGEZERO&type=code) |
| HIGH | [impact/remote_access/net_term]() | uploads, provides a terminal, runs program | [tcsetattr](https://github.com/search?q=tcsetattr&type=code)<br>[_waitpid](https://github.com/search?q=_waitpid&type=code)<br>[_unlink](https://github.com/search?q=_unlink&type=code)<br>[_uname](https://github.com/search?q=_uname&type=code)<br>[execve](https://github.com/search?q=execve&type=code)<br>[upload](https://github.com/search?q=upload&type=code)<br>[shell](https://github.com/search?q=shell&type=code) |
| MEDIUM | [exec/program]() | executes external programs | [execve](https://github.com/search?q=execve&type=code) |
| MEDIUM | [exec/shell/exec]() | executes shell | [/bin/sh](https://github.com/search?q=%2Fbin%2Fsh&type=code) |
| MEDIUM | [impact/remote_access/pseudo_terminal]() | [pseudo-terminal access functions](https://man7.org/linux/man-pages/man3/grantpt.3.html) | [posix_openpt](https://github.com/search?q=posix_openpt&type=code)<br>[unlockpt](https://github.com/search?q=unlockpt&type=code)<br>[grantpt](https://github.com/search?q=grantpt&type=code)<br>[ptsname](https://github.com/search?q=ptsname&type=code) |
| MEDIUM | [net/download]() | download files | [_proc_download_content](https://github.com/search?q=_proc_download_content&type=code) |
| MEDIUM | [net/ip/parse]() | parses IP address | [inet_addr](https://github.com/search?q=inet_addr&type=code) |
| MEDIUM | [net/ip/string]() | [converts IP address from byte to string](https://linux.die.net/man/3/inet_ntoa) | [inet_ntoa](https://github.com/search?q=inet_ntoa&type=code) |
| MEDIUM | [net/socket/connect]() | [initiate a connection on a socket](https://linux.die.net/man/3/connect) | [_connect](https://github.com/search?q=_connect&type=code) |
| LOW | [data/random/insecure]() | [generate random numbers insecurely](https://man.openbsd.org/rand) | [_rand](https://github.com/search?q=_rand&type=code)<br>[srand](https://github.com/search?q=srand&type=code) |
| LOW | [discover/system/platform]() | [system identification](https://man7.org/linux/man-pages/man1/uname.1.html) | [uname](https://github.com/search?q=uname&type=code) |
| LOW | [discover/user/name_get]() | [get login name](https://linux.die.net/man/3/getlogin) | [getlogin](https://github.com/search?q=getlogin&type=code) |
| LOW | [exec/program/background]() | [wait for process to exit](https://linux.die.net/man/2/waitpid) | [waitpid](https://github.com/search?q=waitpid&type=code) |
| LOW | [exec/shell/SHELL]() | [path to active shell](https://man.openbsd.org/login.1#ENVIRONMENT) | [SHELL](https://github.com/search?q=SHELL&type=code) |
| LOW | [fs/file/delete]() | [deletes files](https://man7.org/linux/man-pages/man2/unlink.2.html) | [unlink](https://github.com/search?q=unlink&type=code) |
| LOW | [fs/symlink_resolve]() | [resolves symbolic links](https://man7.org/linux/man-pages/man3/realpath.3.html) | [realpath](https://github.com/search?q=realpath&type=code) |
| LOW | [net/resolve/hostname]() | [resolve network host name to IP address](https://linux.die.net/man/3/gethostbyname) | [gethostbyname](https://github.com/search?q=gethostbyname&type=code) |
| LOW | [net/socket/receive]() | [receive a message from a socket](https://linux.die.net/man/2/recvmsg) | [_recv](https://github.com/search?q=_recv&type=code) |
| LOW | [net/socket/send]() | [send a message to a socket](https://linux.die.net/man/2/sendmsg) | [_send](https://github.com/search?q=_send&type=code) |
| LOW | [os/env/get]() | Retrieve environment variables | [getenv](https://github.com/search?q=getenv&type=code) |
| LOW | [process/create]() | [create child process](https://man7.org/linux/man-pages/man2/fork.2.html) | [_fork](https://github.com/search?q=_fork&type=code) |
| LOW | [process/multithreaded]() | [creates pthreads](https://man7.org/linux/man-pages/man3/pthread_create.3.html) | [pthread_create](https://github.com/search?q=pthread_create&type=code) |

