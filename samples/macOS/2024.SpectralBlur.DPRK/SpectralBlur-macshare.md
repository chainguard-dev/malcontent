## macOS/2024.SpectralBlur.DPRK/SpectralBlur-macshare [🔥 HIGH]

|  RISK  |           KEY           |                DESCRIPTION                 |                                EVIDENCE                                 |
|--------|-------------------------|--------------------------------------------|-------------------------------------------------------------------------|
| HIGH   | combo/backdoor/net_term | uploads, provides a terminal, runs program | _uname<br>_unlink<br>_waitpid<br>execve<br>shell<br>tcsetattr<br>upload |
| MEDIUM | device/pseudo_terminal  | pseudo-terminal access functions           | grantpt<br>posix_openpt<br>ptsname<br>unlockpt                          |
| MEDIUM | exec/program            | executes external programs                 | execve                                                                  |
| MEDIUM | kernel/uname/get        | system identification (uname)              | uname                                                                   |
| MEDIUM | net/download            | download files                             | _proc_download_content                                                  |
| MEDIUM | net/ip/parse            | parses IP address                          | inet_addr                                                               |
| MEDIUM | net/ip/string           | converts IP address from byte to string    | inet_ntoa                                                               |
| MEDIUM | net/socket/connect      | initiate a connection on a socket          | _connect                                                                |
| MEDIUM | net/upload              | uploads files                              | upload                                                                  |
| MEDIUM | shell/exec              | executes shell                             | /bin/sh                                                                 |
| LOW    | env/SHELL               | users preferred SHELL path                 | SHELL                                                                   |
| LOW    | exec/program/background | wait for process to exit                   | waitpid                                                                 |
| LOW    | fs/file/delete          | deletes files                              | unlink                                                                  |
| LOW    | fs/symlink/resolve      | resolves symbolic links                    | realpath                                                                |
| LOW    | net/hostname/resolve    | resolves network hosts via name            | gethostbyname                                                           |
| LOW    | net/socket/receive      | receive a message from a socket            | _recv                                                                   |
| LOW    | net/socket/send         | send a message to a socket                 | _send                                                                   |
| LOW    | process/create          | create a new child process using fork      | _fork                                                                   |
| LOW    | process/multithreaded   | creates pthreads                           | pthread_create                                                          |
| LOW    | process/username/get    | get login name                             | getlogin                                                                |
| LOW    | random/insecure         | generate random numbers insecurely         | _rand<br>srand                                                          |

