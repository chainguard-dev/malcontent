rule hide_shell_history: high {
  meta:
    description = "Hides shell command history"

  strings:
    $hide_this       = "HIDE_THIS"
    $histfile        = "HISTFILE=" fullword
    $histfile_dev    = /HISTFILE=\/(dev|tmp)[\/\w]{0,16}/
    $histcontrol     = /HISTCONTROL=\"*ignorespace/
    $h_shopt_history = "shopt -ou history"
    $h_set_o_history = "set +o history"
    $histsize_0      = "HISTSIZE=0"
    $not_increment   = "HISTSIZE++"

  condition:
    any of ($h*) and none of ($not*)
}

rule histfile_savehist_ld: high {
  meta:
    description = "likely hides shell command history"

  strings:
    $HISTFILE = "HISTFILE"
    $SAVEHIST = "SAVEHIST"
    $LD_DEBUG = "LD_DEBUG"

  condition:
    filesize < 250KB and all of them
}
