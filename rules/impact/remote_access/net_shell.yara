rule netcat_exec_backdoor: high {
  meta:
    ref = "https://cert.gov.ua/article/6123309"

  strings:
    $nc_e = "nc -e "

  condition:
    filesize < 10485760 and all of them
}

rule generic_perl_socket_exec {
  strings:
    $perl         = "perl"
    $socket_inet  = "IO::Socket::INET"
    $socket       = "use Socket"
    $and_exec     = "exec"
    $and_system   = "system("
    $and_backtick = "`;"
    $not_nuclei   = "NUCLEI_TEMPLATES"
    $not_kitten   = "KITTY_KITTEN_RUN_MODULE"

  condition:
    filesize < 1048576 and $perl and any of ($socket*) and any of ($and_*) and none of ($not_*)
}

rule ipinfo_and_bash: high {
  meta:
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"

  strings:
    $ipinfo = "ipinfo.io"
    $bash   = "/bin/bash"

  condition:
    all of them
}

rule readdir_inet_system: high {
  meta:
    description              = "Lists directories, resolves IPs, calls shells"
    hash_2023_Lightning_48f9 = "48f9471c20316b295704e6f8feb2196dd619799edec5835734fc24051f45c5b7"

  strings:
    $dlsym   = "readdir" fullword
    $openpty = "inet_addr" fullword
    $system  = "system" fullword

  condition:
    all of them in (1000..3000)
}

rule pcap_shell_exec: high {
  meta:
    description                = "sniffs network traffic, executes shell"
    hash_2023_BPFDoor_dc83     = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
    hash_2024_enumeration_nmap = "353fd20c9efcd0328cea494f32d3650b9346fcdb45bfe20d8dbee2dd7b62ca62"

    filetypes = "elf,macho"

  strings:
    $libpcap      = "libpcap"
    $shell        = "shell" fullword
    $sh           = "/bin/sh"
    $sh_bash      = "/bin/bash"
    $y_exec       = "exec" fullword
    $y_execve     = "execve" fullword
    $y_execvp     = "execvp" fullword
    $y_system     = "system" fullword
    $not_airportd = "airportd"
    $not_license  = "Alternate form in libpcap, which also omits the IN NO EVENT paragraph"

  condition:
    filesize < 10MB and filesize > 20KB and $libpcap and any of ($sh*) and any of ($y*) and none of ($not*)
}

rule go_pty_daemonize_net: critical {
  meta:
    description = "daemonizes and exposes a terminal to the internet"

    hash_2024_termite_termite_linux_arm = "d36b8cfef77149c64cb203e139657d5219527c7cf4fee45ca302d89b7ef851e6"
    hash_2024_termite_main              = "d9c819b4e14a64033d0188a83dab05771a1914f00a14e8cc12f96e5d0c4f924a"

  strings:
    $d1      = "go-daemon" fullword
    $d2      = "xdaemon" fullword
    $pty     = "creack/pty" fullword
    $ptsname = "ptsname" fullword
    $net     = "net.socket" fullword
    $nsocks  = "go-socks5"

  condition:
    any of ($d*) and any of ($p*) and any of ($n*)
}

rule dropshell: high {
  meta:
    description = "provides remote shell access"

  strings:
    $ = "dropshell" fullword
    $ = "/bin/bash" fullword
    $ = "execve" fullword
    $ = "accept" fullword
    $ = "inet_"

  condition:
    filesize < 1MB and all of them
}
