
rule kill_and_remove : notable {
  meta:
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
  strings:
    $rm_f = "rm -f"
    $rm_Rf = "rm -Rf"
    $rm_rf = "rm -rf"
    $k_killall = "killall"
    $k_pgrep = "pgrep"
    $k_pkill = "pkill"
    $not_shell_help = "$progname: "
    $not_tempdir = "rm -rf \"$TEMPDIR\""
  condition:
    1 of ($rm*) and 1 of ($k*) and none of ($not*)
}
