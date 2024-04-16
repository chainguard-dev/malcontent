## macOS/2024.SpectralBlur.DPRK/SpectralBlur-macshare

Overall risk: 🔥 3/HIGH

|   RISK   |           KEY           |                     DESCRIPTION                     |
|----------|-------------------------|-----------------------------------------------------|
| meta     | format                  | macho                                               |
|          |                         |                                                     |
| 3/HIGH   | combo/backdoor/net_term | uploads, provides a terminal, runs program: "_uname |
|          |                         | _unlink                                             |
|          |                         | _waitpid                                            |
|          |                         | execve                                              |
|          |                         | shell                                               |
|          |                         | tcsetattr                                           |
|          |                         | upload"                                             |
| 2/MEDIUM | device/pseudo_terminal  | pseudo-terminal access functions                    |
| 2/MEDIUM | exec/program            | executes external programs                          |
| 2/MEDIUM | kernel/uname/get        | get system identification (uname)                   |
| 2/MEDIUM | net/download            | downloads files                                     |
| 2/MEDIUM | net/ip/parse            | parses IP address                                   |
| 2/MEDIUM | net/ip/string           | converts IP address from byte to string             |
| 2/MEDIUM | net/socket/connect      | initiate a connection on a socket                   |
| 2/MEDIUM | net/upload              | uploads files                                       |
| 2/MEDIUM | shell/exec              | executes a shell                                    |
| 1/LOW    | env/SHELL               | users preferred SHELL path                          |
| 1/LOW    | exec/program/background | waits for a process to exit                         |
| 1/LOW    | fs/file/delete          | deletes files                                       |
| 1/LOW    | fs/symlink/resolve      | resolves symbolic links                             |
| 1/LOW    | net/hostname/resolve    | resolves network hosts via name                     |
| 1/LOW    | net/socket/receive      | receive a message from a socket                     |
| 1/LOW    | net/socket/send         | send a message to a socket                          |
| 1/LOW    | process/create          | create a new child process using fork               |
| 1/LOW    | process/multithreaded   | uses pthreads                                       |
| 1/LOW    | process/username/get    | get login name                                      |
| 1/LOW    | random/insecure         | generate random numbers insecurely                  |

