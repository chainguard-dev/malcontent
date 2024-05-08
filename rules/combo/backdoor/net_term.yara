
rule readdir_openpty_socket : suspicious {
  meta:
    description = "Lists directories, opens pseudoterminals, resolves IPs"
  strings:
    $dlsym = "readdir" fullword
    $openpty = "openpty" fullword
    $system = "inet_addr" fullword
  condition:
    all of them in (1200..3000)
}

rule pseudoterminal_tunnel : suspicious {
  meta:
    description = "pseudoterminal and tunnel support"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
  strings:
    $pty = "creack/pty" fullword
    $ptsname = "ptsname" fullword
    $t = /[\w]{0,16}tunnel[\w]{0,16}/ fullword
    $t2 = /[\w]{0,16}TUNNEL[\w]{0,16}/ fullword
    $not_qemu = "QEMU_IS_ALIGNED"
    $not_unbounded = "UNBOUNDED"
    $not_iot = "iotsecuredtunnel"
  condition:
    any of ($p*) and any of ($t*) and none of ($not*)
}

rule tty_shell : suspicious {
  strings:
    $s_tty_shell = "tty shell" nocase
    $s_SSLshell = /SSL *Shell/ nocase
    $s_shellChannel = "ShellChannel"
    $not_login = "login_shell"
  condition:
    filesize < 26214400 and any of ($s*) and none of ($not*)
}

rule python_pty_spawner : suspicious {
  meta:
    ref1 = "https://juggernaut-sec.com/docker-breakout-lpe/"
    ref2 = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
  strings:
    $pty_spawn_bash = /pty.spawn\(\"\/bin\/[\w\" -\)]{,16}/
  condition:
    any of them
}

rule spectralblur_alike : suspicious {
  meta:
    description = "uploads, provides a terminal, runs program"
  strings:
    $upload = "upload"
    $shell = "shell"
    $tcsetattr = "tcsetattr"
    $execve = "execve"
    $waitpid = "_waitpid"
    $unlink = "_unlink"
    $uname = "_uname"
  condition:
    all of them
}

rule miner_kvryr_stak_alike : suspicious {
  meta:
    description = "uploads, provides a terminal, runs program"
  strings:
    $upload = "upload"
    $shell = "shell"
    $tcsetattr = "tcsetattr"
    $execve = "execve"
    $numa = "NUMA"
  condition:
    filesize < 67108864 and all of them
}

rule proxy_http_aes_terminal_combo : notable {
  strings:
    $isatty = "isatty"
    $socks_proxy = "socks proxy"
    $socks = "SOCKS"
    $http = "http://"
    $http_req = "http request"
    $aes_gcm = "AESGCM"
    $aes_256 = "AES-256"
  condition:
    filesize < 26214400 and 85% of them
}

rule bpfdoor_alike : suspicious {
  meta:
    description = "Listens, provides a terminal, runs program"
    hash_2023_BPFDoor_07ec = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
    hash_2023_BPFDoor_3743 = "3743821d55513c52a9f06d3f6603afd167105a871e410c35a3b94e34c51089e6"
    hash_2023_BPFDoor_8b9d = "8b9db0bc9152628bdacc32dab01590211bee9f27d58e0f66f6a1e26aea7552a6"
  strings:
    $f_listen = "listen" fullword
    $f_grantpt = "grantpt" fullword
    $f_execve = "execve" fullword
    $f_ptmx = "/dev/ptmx"
    $not_sql_db = "sql.DB"
    $not_libc = "getusershell"
  condition:
    all of ($f*) and none of ($not*)
}

rule dlsym_openpty_system : suspicious {
  meta:
    description = "Resolves library, opens terminal, calls shell"
  strings:
    $dlsym = "dlsym" fullword
    $openpty = "openpty" fullword
    $system = "system"
  condition:
    all of them in (1200..3000)
}
