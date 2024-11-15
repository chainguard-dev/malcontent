rule macos_kitchen_sink_binary: medium {
  meta:
    description = "likely remote control service"

  strings:
    $f_sysctl        = "sysctl"
    $f_mkdtemp       = "mkdtemp"
    $f_mktemp        = "mktemp"
    $f_inet_addr     = "inet_addr"
    $f_waitpid       = "waitpid"
    $f_proc_listpids = "proc_listpids"
    $f_kill          = "kill"
    $f_chdir         = "chdir"
    $f_setsockopt    = "setsockopt"
    $f_getpid        = "getpid"
    $f_unlink        = "unlink"
    $f_chmod         = "chmod"
    $not_osquery     = "OSQUERY"

  condition:
    filesize < 20971520 and 90 % of ($f*) and none of ($not*)
}

rule ssh_socks5_exec: medium {
  meta:
    description = "supports SOCKS5, SSH, and executing programs"

  strings:
    $socks5 = "Socks5"
    $ssh    = "crypto/ssh"
    $exec   = "os/exec.Command"

  condition:
    filesize < 67108864 and all of them
}

rule progname_socket_waitpid: high {
  meta:
    description = "sets process name, accesses internet, calls programs"

  strings:
    $dlsym   = "__progname" fullword
    $openpty = "socket" fullword
    $system  = "waitpid" fullword

  condition:
    all of them in (1000..3000)
}

rule POST_command_executer: high {
  meta:
    description = "executes commands, uploads content"

  strings:
    $post             = "POST"
    $command_executed = "Command executed"

  condition:
    all of them
}

rule exec_getprog_socket_waitpid_combo: high {
  meta:
    description = "executes commands, accesses internet sites"

  strings:
    $execle          = "_execl"
    $execve          = "_execve"
    $f_fork          = "_fork"
    $f_getpid        = "_getpid"
    $f_inet          = "_inet_ntoa"
    $f_getprog       = "_getprogname"
    $f_gethostbyname = "_gethostbyname"
    $f_socket        = "_socket"
    $f_waitpid       = "_waitpid"
    $f_rand          = "_random"

  condition:
    filesize < 262144000 and 8 of ($f*) and 1 of ($exec*)
}

rule exec_chdir_and_socket: medium {
  meta:
    description = "executes commands, changes directories, accesses remote hosts"

  strings:
    $socket      = "socket" fullword
    $chdir       = "chdir" fullword
    $execl       = "execl" fullword
    $execve      = "execve" fullword
    $not_environ = "environ" fullword

  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $chdir and $socket and 1 of ($exec*) and none of ($not*)
}

rule lazarus_darwin: high {
  meta:
    description = "executes programs, sets permissions, sleeps, resolves hostnames"

  strings:
    $pclose      = "pclose" fullword
    $popen       = "popen" fullword
    $sleep       = "sleep" fullword
    $rand        = "rand" fullword
    $strncpy     = "strncpy" fullword
    $gethostname = "gethostname" fullword
    $localtime   = "localtime" fullword
    $sprintf     = "sprintf" fullword
    $chmod       = "chmod" fullword
    $flock       = "flock" fullword
    $NSURL       = "NSMutableURLRequest" fullword

  condition:
    filesize < 6MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and 90 % of them
}

rule lazarus_darwin_nsurl: critical {
  meta:
    description = "executes programs, sets permissions, sleeps, makes HTTP requests"

  strings:
    $pclose      = "pclose" fullword
    $popen       = "popen" fullword
    $sleep       = "sleep" fullword
    $rand        = "rand" fullword
    $strncpy     = "strncpy" fullword
    $gethostname = "gethostname" fullword
    $localtime   = "localtime" fullword
    $sprintf     = "sprintf" fullword
    $chmod       = "chmod" fullword
    $flock       = "flock" fullword
    $NSURL       = "NSMutableURLRequest" fullword

  condition:
    filesize < 6MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and all of them
}

rule lazarus_darwin_applejeus: critical {
  meta:
    description = "executes programs, sets permissions, sleeps, makes HTTP requests"

  strings:
    $pclose      = "time" fullword
    $popen       = "popen" fullword
    $sleep       = "sleep" fullword
    $rand        = "rand" fullword
    $strncpy     = "strncpy" fullword
    $gethostname = "gethostname" fullword
    $localtime   = "localtime" fullword
    $sprintf     = "sprintf" fullword
    $chmod       = "chmod" fullword
    $flock       = "flock" fullword
    $NSURL       = "NSMutableURLRequest" fullword

  condition:
    filesize < 6MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and all of them
}

rule tinyshell_callme_like: high {
  meta:
    description = "executes programs, sleeps, makes outgoing connections"

  strings:
    $pclose      = "time" fullword
    $popen       = "popen" fullword
    $sleep       = "sleep" fullword
    $strncpy     = "strncpy" fullword
    $sprintf     = "sprintf" fullword
    $sh          = "/bin/bash"
    $socket      = "socket" fullword
    $gethostname = "gethostbyname" fullword
    $system      = "system" fullword
    $wait        = "wait" fullword

    $getlogin = "getlogin" fullword
    $fwrite   = "fwrite" fullword

  condition:
    filesize < 200KB and all of them
}

rule aes_tinyshell_callme_like: critical {
  meta:
    description = "executes programs, sleeps, makes AES encrypted connections"

  strings:
    $pclose      = "time" fullword
    $popen       = "popen" fullword
    $sleep       = "sleep" fullword
    $strncpy     = "strncpy" fullword
    $sprintf     = "sprintf" fullword
    $sh          = "/bin/bash"
    $socket      = "socket" fullword
    $gethostname = "gethostbyname" fullword
    $system      = "system" fullword
    $wait        = "wait" fullword

    $getlogin    = "getlogin" fullword
    $fwrite      = "fwrite" fullword
    $aes_encrypt = "aes_encrypt" fullword

  condition:
    filesize < 250KB and all of them
}
