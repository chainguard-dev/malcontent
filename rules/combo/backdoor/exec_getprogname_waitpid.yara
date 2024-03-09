rule exec_getprog_socket_waitpid_combo {
  meta:
    hash_DoubleFantasy_mdworker = "502a80f81cf39f6c559ab138a39dd4ad5fca697dbca4a62b36527be9e55400f5"
  strings:
    $execle = "_execl"
    $execve = "_execve"
    $f_fork = "_fork"
    $f_getpid = "_getpid"
    $f_inet = "_inet_ntoa"
    $f_getprog = "_getprogname"
    $f_gethostbyname = "_gethostbyname"
    $f_socket = "_socket"
    $f_waitpid = "_waitpid"
    $f_rand = "_random"
  condition:
    8 of ($f*) and 1 of ($exec*)
}
