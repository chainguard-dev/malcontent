## macOS/2024.SpectralBlur.DPRK/SpectralBlur-macshare

Overall risk: 🔥 HIGH

|   RISK   |           KEY           |                DESCRIPTION                 |                                EVIDENCE                                 |
|----------|-------------------------|--------------------------------------------|-------------------------------------------------------------------------|
| 3/HIGH   | combo/backdoor/net_term | uploads, provides a terminal, runs program | _uname<br>_unlink<br>_waitpid<br>execve<br>shell<br>tcsetattr<br>upload |
| 2/MEDIUM | device/pseudo_terminal  | pseudo-terminal access functions           | grantpt<br>posix_openpt<br>ptsname<br>unlockpt                          |
| 2/MEDIUM | exec/program            | executes external programs                 | execve                                                                  |
| 2/MEDIUM | kernel/uname/get        | get system identification                  | uname                                                                   |
| 2/MEDIUM | net/download            | download files                             | _proc_download_content                                                  |
| 2/MEDIUM | net/ip/parse            | parses IP address                          | inet_addr                                                               |
| 2/MEDIUM | net/ip/string           | converts IP address from byte to string    | inet_ntoa                                                               |
| 2/MEDIUM | net/socket/connect      | initiate a connection on a socket          | _connect                                                                |
| 2/MEDIUM | net/upload              | uploads files                              | upload                                                                  |
| 2/MEDIUM | shell/exec              | executes shell                             | /bin/sh                                                                 |
| 1/LOW    | env/SHELL               | users preferred SHELL path                 | SHELL                                                                   |
| 1/LOW    | exec/program/background | wait for process to exit                   | waitpid                                                                 |
| 1/LOW    | fs/file/delete          | deletes files                              | unlink                                                                  |
| 1/LOW    | fs/symlink/resolve      | resolves symbolic links                    | realpath                                                                |
| 1/LOW    | net/hostname/resolve    | resolves network hosts via name            | gethostbyname                                                           |
| 1/LOW    | net/socket/receive      | receive a message from a socket            | _recv                                                                   |
| 1/LOW    | net/socket/send         | send a message to a socket                 | _send                                                                   |
| 1/LOW    | process/create          | create a new child process using fork      | _fork                                                                   |
| 1/LOW    | process/multithreaded   | uses pthreads                              | pthread_create                                                          |
| 1/LOW    | process/username/get    | get login name                             | getlogin                                                                |
| 1/LOW    | random/insecure         | generate random numbers insecurely         | _rand<br>srand                                                          |

