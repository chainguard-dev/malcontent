rule netcat_exec_backdoor: high {
  meta:
    ref         = "https://cert.gov.ua/article/6123309"
    description = "netcat backdoor"

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
    description = "runs bash, gets external IP"

  strings:
    $ipinfo = "ipinfo.io"
    $bash   = "/bin/bash"

  condition:
    all of them
}

rule readdir_inet_system: high {
  meta:
    description = "Lists directories, resolves IPs, calls shells"

  strings:
    $dlsym   = "readdir" fullword
    $openpty = "inet_addr" fullword
    $system  = "system" fullword

  condition:
    all of them in (1000..3000)
}

rule pcap_shell_exec: high {
  meta:
    description = "sniffs network traffic, executes shell"

    filetypes = "elf,macho"

  strings:
    $libpcap        = "libpcap"
    $shell          = "shell" fullword
    $sh             = "/bin/sh"
    $sh_bash        = "/bin/bash"
    $y_exec         = "exec" fullword
    $y_execve       = "execve" fullword
    $y_execvp       = "execvp" fullword
    $y_system       = "system" fullword
    $not_airportd   = "airportd"
    $not_license    = "Alternate form in libpcap, which also omits the IN NO EVENT paragraph"
    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 10MB and filesize > 20KB and $libpcap and any of ($sh*) and any of ($y*) and none of ($not*)
}

rule go_pty_daemonize_net: high {
  meta:
    description = "daemonizes and exposes a terminal to the internet"

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
