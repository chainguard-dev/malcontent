
rule exec_chdir_and_socket : suspicious {
  strings:
    $socket = "socket" fullword
    $chdir = "chdir" fullword
    $execl = "execl" fullword
    $execve = "execve" fullword
    $not_environ = "_environ"
  condition:
    $chdir and $socket and 1 of ($exec*) and none of ($not*)
}