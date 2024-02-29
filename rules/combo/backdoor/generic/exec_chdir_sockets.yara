
rule exec_chdir_and_socket : suspicious {
  strings:
    $socket = "socket" fullword
    $chdir = "chdir" fullword
    $execl = "execl" fullword
    $execve = "execve" fullword
    $not_environ = "environ" fullword
  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $chdir and $socket and 1 of ($exec*) and none of ($not*)
}