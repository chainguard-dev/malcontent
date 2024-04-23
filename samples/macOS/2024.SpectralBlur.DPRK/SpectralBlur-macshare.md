## macOS/2024.SpectralBlur.DPRK/SpectralBlur-macshare [🔥 HIGH]

|  RISK  |           KEY           |                     DESCRIPTION                     |
|--------|-------------------------|-----------------------------------------------------|
| meta   | format                  | macho                                               |
|        |                         |                                                     |
| HIGH   | combo/backdoor/net_term | uploads, provides a terminal, runs program: "_uname |
|        |                         | _unlink                                             |
|        |                         | _waitpid                                            |
|        |                         | execve                                              |
|        |                         | shell                                               |
|        |                         | tcsetattr                                           |
|        |                         | upload"                                             |
| MEDIUM | device/pseudo_terminal  | pseudo-terminal access functions                    |
| MEDIUM | exec/program            | executes external programs                          |
| MEDIUM | kernel/uname/get        | get system identification                           |
| MEDIUM | net/download            | download files                                      |
| MEDIUM | net/ip/parse            | parses IP address                                   |
| MEDIUM | net/ip/string           | converts IP address from byte to string             |
| MEDIUM | net/socket/connect      | initiate a connection on a socket                   |
| MEDIUM | net/upload              | uploads files                                       |
| MEDIUM | shell/exec              | executes shell                                      |
| LOW    | env/SHELL               | users preferred SHELL path                          |
| LOW    | exec/program/background | wait for process to exit                            |
| LOW    | fs/file/delete          | deletes files                                       |
| LOW    | fs/symlink/resolve      | resolves symbolic links                             |
| LOW    | net/hostname/resolve    | resolves network hosts via name                     |
| LOW    | net/socket/receive      | receive a message from a socket                     |
| LOW    | net/socket/send         | send a message to a socket                          |
| LOW    | process/create          | create a new child process using fork               |
| LOW    | process/multithreaded   | uses pthreads                                       |
| LOW    | process/username/get    | get login name                                      |
| LOW    | random/insecure         | generate random numbers insecurely                  |

