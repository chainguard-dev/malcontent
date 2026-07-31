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
    // "rm -rf" is a literal prefix of the accepted `rm -rf "$TEMPDIR"` cleanup
    // line, so count that spelling off instead of letting it hide every other
    // rm -rf in the file. $not_shell_help is unrelated and stays independent.
    (#rm_f > 0 or #rm_Rf > 0 or #rm_rf > #not_tempdir) and
    1 of ($k*) and
    none of ($not_shell_help)
}
