rule tty_shell : suspicious {
  meta:
    hash_2023_trojan_seaspy_barracuda = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115"
  strings:
    $s_tty_shell = "tty shell" nocase
    $s_SSLshell = /SSL *Shell/ nocase
    $s_shellChannel = "ShellChannel"
    $not_login = "login_shell"
  condition:
    filesize < 26214400 and any of ($s*) and none of ($not*)
}
