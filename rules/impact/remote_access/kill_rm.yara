rule kill_and_remove: medium {
  meta:
    description = "kills and removes programs via the command-line"

  strings:
    $rm_f           = "rm -f"
    $rm_Rf          = "rm -Rf"
    $rm_rf          = "rm -rf"
    $k_killall      = "killall"
    $k_pgrep        = "pgrep"
    $k_pkill        = "pkill"
    $not_shell_help = "$progname: "
    $not_tempdir    = "rm -rf \"$TEMPDIR\""

  condition:
    1 of ($rm*) and 1 of ($k*) and none of ($not*)
}
