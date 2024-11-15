rule readdir_openpty_socket: high {
  meta:
    description = "Lists directories, opens pseudoterminals, resolves IPs"

  strings:
    $dlsym   = "readdir" fullword
    $openpty = "openpty" fullword
    $system  = "inet_addr" fullword

  condition:
    all of them in (1000..3000)
}

rule pseudoterminal_tunnel: high {
  meta:
    description = "pseudoterminal and tunnel support"

  strings:
    $pty           = "creack/pty" fullword
    $ptsname       = "ptsname" fullword
    $t             = /[\w]{0,16}tunnel[\w]{0,16}/ fullword
    $t2            = /[\w]{0,16}TUNNEL[\w]{0,16}/ fullword
    $not_qemu      = "QEMU_IS_ALIGNED"
    $not_unbounded = "UNBOUNDED"
    $not_iot       = "iotsecuredtunnel"

  condition:
    filesize < 100KB and any of ($p*) and any of ($t*) and none of ($not*)
}

rule tty_shell: high {
  strings:
    $s_tty_shell    = "tty shell" nocase
    $s_SSLshell     = /SSL *Shell/ nocase
    $s_shellChannel = "ShellChannel"
    $not_login      = "login_shell"

  condition:
    filesize < 26214400 and any of ($s*) and none of ($not*)
}

rule python_pty_spawner: high {
  meta:
    ref1 = "https://juggernaut-sec.com/docker-breakout-lpe/"
    ref2 = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

  strings:
    $pty_spawn_bash = /pty.spawn\(\"\/bin\/[\w\" -\)]{,16}/

  condition:
    any of them
}

rule spectralblur_alike: high {
  meta:
    description = "uploads, provides a terminal, runs program"

  strings:
    $upload    = "upload"
    $shell     = "shell"
    $tcsetattr = "tcsetattr"
    $execve    = "execve"
    $waitpid   = "_waitpid"
    $unlink    = "_unlink"
    $uname     = "_uname"

  condition:
    filesize < 200KB and all of them
}

rule miner_kvryr_stak_alike: high {
  meta:
    description = "uploads, provides a terminal, runs program"

  strings:
    $f_upload    = "upload"
    $f_shell     = "shell" fullword
    $f_bin_sh    = "/bin/"
    $f_tcsetattr = "tcsetattr"
    $f_termios   = "termios" fullword
    $f_execve    = "execve"
    $f_numa      = "NUMA"

    $not_perf = "PERF_RECORD"

  condition:
    filesize < 12MB and all of ($f*) and none of ($not*)
}

rule proxy_http_aes_terminal_combo: medium {
  meta:
    description = "uses socks proxy, aes, ands terminal functions"

  strings:
    $isatty      = "isatty"
    $socks_proxy = "socks proxy"
    $socks       = "SOCKS"
    $http        = "http://"
    $http_req    = "http request"
    $aes_gcm     = "AESGCM"
    $aes_256     = "AES-256"

  condition:
    filesize < 26214400 and 85 % of them
}

rule bpfdoor_alike: high {
  meta:
    description = "Listens, provides a terminal, runs program"

  strings:
    $f_listen   = "listen" fullword
    $f_grantpt  = "grantpt" fullword
    $f_execve   = "execve" fullword
    $f_ptmx     = "/dev/ptmx"
    $not_sql_db = "sql.DB"
    $not_libc   = "getusershell"

  condition:
    all of ($f*) and none of ($not*)
}

rule dlsym_openpty_system: high {
  meta:
    description = "Resolves library, opens terminal, calls shell"

  strings:
    $dlsym   = "dlsym" fullword
    $openpty = "openpty" fullword
    $system  = "system"

  condition:
    all of them in (1000..3000)
}

rule ssl_backdoor: high {
  meta:
    description = "SSL backdoor with hardcoded certificate (Rekoobe-like)"

  strings:
    $f_ssl_read  = "SSL_read" fullword
    $f_openpty   = "openpty" fullword
    $f_inet_ntoa = "inet_ntoa" fullword
    $f_fork      = "fork" fullword
    $f_exec      = /exec(l|ve)/ fullword
    $f_socket    = "socket" fullword
    $f_listen    = "listen" fullword
    $f_select    = "select" fullword
    $f_ttyname   = "ttyname" fullword
    $sh          = "/bin/sh"
    $sh_bash     = "bash" fullword
    $sh_bin_bash = "/bin/bash"

    $cert = "-----BEGIN CERTIFICATE-----"
    $key  = /MII[DE][\w\+]{0,64}/

  condition:
    filesize < 100KB and 90 % of ($f*) and any of ($sh*) and $cert and $key
}

rule libev_webshell: high {
  meta:
    description = "libev powered network shell"

  strings:
    $getaddrinfo = "getaddrinfo" fullword
    $forkpty     = "forkpty" fullword
    $exec        = /exec[vl]e{0,1}/ fullword
    $ev_start    = "ev_start" fullword

  condition:
    filesize < 500KB and all of them
}
