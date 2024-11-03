rule readdir_openpty_socket: high {
  meta:
    description              = "Lists directories, opens pseudoterminals, resolves IPs"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

  strings:
    $dlsym   = "readdir" fullword
    $openpty = "openpty" fullword
    $system  = "inet_addr" fullword

  condition:
    all of them in (1000..3000)
}

rule pseudoterminal_tunnel: high {
  meta:
    description                           = "pseudoterminal and tunnel support"
    hash_2023_OK_ad69                     = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2024_termite_termite_linux_amd64 = "fa8d2c01cf81a052ea46650418afa358252ce6f9ce2eb65df3b3e3c7165f8d92"
    hash_2024_termite_termite_linux_arm   = "d36b8cfef77149c64cb203e139657d5219527c7cf4fee45ca302d89b7ef851e6"

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
    ref1                             = "https://juggernaut-sec.com/docker-breakout-lpe/"
    ref2                             = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
    hash_2021_10Cent10_999_0_4_setup = "957129c09d47807d62369cc538041a31c48402df45433b8c4c506459c0bf2e2c"
    hash_2021_10Cent11_999_0_4_setup = "7b8ff20eda43223a4d7d2380093a5fd8cd996542644b7c41a8bf9b686b966c89"
    hash_2024_class_py_1_0_0_setup   = "ebcd4d091dad0cbd946df2f0fe79d67ccd2aa7c315994b2a1e92c8de08e7a9b9"

  strings:
    $pty_spawn_bash = /pty.spawn\(\"\/bin\/[\w\" -\)]{,16}/

  condition:
    any of them
}

rule spectralblur_alike: high {
  meta:
    description                     = "uploads, provides a terminal, runs program"
    hash_2024_SpectralBlur_macshare = "6f3e849ee0fe7a6453bd0408f0537fa894b17fc55bc9d1729ae035596f5c9220"

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
    description                          = "uploads, provides a terminal, runs program"
    hash_2023_Linux_Malware_Samples_1b1a = "1b1a56aec5b02355b90f911cdd27a35d099690fcbeb0e0622eaea831d64014d3"
    hash_2023_Linux_Malware_Samples_240f = "240fe01d9fcce5aae311e906b8311a1975f8c1431b83618f3d11aeaff10aede3"
    hash_2023_Linux_Malware_Samples_39c3 = "39c33c261899f2cb91f686aa6da234175237cd72cfcd9291a6e51cbdc86d4def"

  strings:
    $upload    = "upload"
    $shell     = "shell" fullword
    $bin_sh    = "/bin/"
    $tcsetattr = "tcsetattr"
    $termios   = "termios" fullword
    $execve    = "execve"
    $numa      = "NUMA"

  condition:
    filesize < 12MB and all of them
}

rule proxy_http_aes_terminal_combo: medium {
  meta:
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2023_Linux_Malware_Samples_19f7 = "19f76bf2be3ea11732f2c5c562afbd6f363b062c25fba3a143c3c6ef4712774b"

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
    description            = "Listens, provides a terminal, runs program"
    hash_2023_BPFDoor_07ec = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
    hash_2023_BPFDoor_3743 = "3743821d55513c52a9f06d3f6603afd167105a871e410c35a3b94e34c51089e6"
    hash_2023_BPFDoor_8b9d = "8b9db0bc9152628bdacc32dab01590211bee9f27d58e0f66f6a1e26aea7552a6"

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
    description              = "Resolves library, opens terminal, calls shell"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

  strings:
    $dlsym   = "dlsym" fullword
    $openpty = "openpty" fullword
    $system  = "system"

  condition:
    all of them in (1000..3000)
}
