rule reverse_shell: high {
  meta:
    description = "references a reverse shell"

  strings:
    $r_bash_dev_tcp         = "bash -i >& /dev/tcp/"
    $r_reverse_or_web_shell = /(r[e3]v[e3]rs[e3]|w[3e]b)\s*sh[e3]ll/ nocase
    $r_reverse_shell        = "reverse_shell"
    $r_reverse_space_shell  = "reverse shell" nocase fullword
    $r_revshell             = "revshell"
    $r_stdin_redir          = "0>&1" fullword
    $not_elastic            = "\"license\": \"Elastic License v2\""
    $not_ref_1              = "reverse shellConf"
    $not_ref_2              = "reverse shellshare"
    $not_pypi_index         = "testpack-id-lb001"

  condition:
    any of ($r_*) and none of ($not_*)
}

rule possible_reverse_shell: medium {
  meta:
    description = "references a reverse shell"

  strings:
    $f_reverse = "reverse"
    $f_socket  = "socket" fullword
    $sh_bash   = "/bin/bash"
    $sh        = "/bin/sh"

    $not_elastic    = "\"license\": \"Elastic License v2\""
    $not_uc2        = "ucs2reverse"
    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 4MB and any of ($sh*) and all of ($f*) and none of ($not*)
}

rule mkfifo_netcat: critical {
  meta:
    description = "creates a reverse shell using mkfifo and netcat"

  strings:
    $mkfifo = "mkfifo" fullword
    $sh_i   = "sh -i"
    $nc     = /\| {0,2}nc /

  condition:
    filesize < 16384 and all of them
}

rule perl_reverse_shell: critical {
  meta:
    description = "reverse shell in Perl"

  strings:
    $socket       = "socket("
    $open         = "open("
    $redir_double = "\">&"
    $redir_single = "'>&"
    $sh_i         = "sh -i"

    $not_comment1 = "Upgrade all instances of lodash to the latest release, but ask confirmation for each"
    $not_comment2 = "$0 up lodash -i"
    $not_yarn1    = "If the package is not specified, Yarn will default to the current workspace."
    $not_yarn2    = "yarn npm"
    $not_yarn3    = "@yarnpkg"
    $not_yarn4    = "YARN_"

  condition:
    $socket and $open and any of ($redir*) and $sh_i and none of ($not*)
}

rule go_reverse_shell: high {
  meta:
    description = "possible reverse shell written in Go"

  strings:
    $sh_bash    = "/bin/bash"
    $sh         = "/bin/sh"
    $f_cmd_run  = "os/exec.(*Cmd).Run"
    $f_net_conn = "net.(*conn).Write"
    $f_stdin    = "os/exec.(*Cmd).childStdin"
    $f_tcp      = "dialTCP"

  condition:
    filesize < 4MB and any of ($sh*) and all of ($f*)
}

rule ruby_reverse_shell: high {
  meta:
    description = "reverse shell written in Ruby"

  strings:
    $spawn_tcpsocket = /spawn\(["']\/bin\/sh["'],.{0,64}TCPSocket.{0,64}\)/
    $popen_socket    = /TCPSocket.{0,64}\.gets.{0,64}IO.popen.{0,32}/
    $tcp_sh_i        = /TCPSocket.{0,64}\/bin\/sh -i/

  condition:
    filesize < 64KB and any of them
}

rule ruby_tcpsocket_popen: high {
  meta:
    description = "reverse shell written in Ruby"

  strings:
    $socket      = /TCPSocket\.[\w]{2,8}/
    $popen       = /\.popen\w{0,2}\(["'\w \.\#\{\}]{0,64}/
    $gets        = /\w{1,16}\.gets/
    $copy_stream = "IO.copy_stream"

  condition:
    filesize < 64KB and all of them
}

rule ruby_sneaky_socket: high {
  meta:
    description = "reverse shell written in Ruby"

  strings:
    $socket  = /Socket\.new/
    $connect = /\w{1,8}\.connect/
    $bin_sh  = "/bin/sh -i"
    $fd      = "fd" fullword

  condition:
    filesize < 64KB and all of them
}
