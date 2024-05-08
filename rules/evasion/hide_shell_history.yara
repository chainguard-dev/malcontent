
rule hide_shell_history : suspicious {
  meta:
    description = "Hides shell command history"
    hash_2023_BPFDoor_8b9d = "8b9db0bc9152628bdacc32dab01590211bee9f27d58e0f66f6a1e26aea7552a6"
    hash_2023_BPFDoor_93f4 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
    hash_2023_BPFDoor_dc83 = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
  strings:
    $hide_this = "HIDE_THIS"
    $histfile = "HISTFILE=" fullword
    $histfile_dev = "HISTFILE=/dev"
    $histcontrol = /HISTCONTROL=\"*ignorespace/
    $h_shopt_history = "shopt -ou history"
    $h_set_o_history = "set +o history"
    $histsize_0 = "HISTSIZE=0"
    $h_gotcha = "GOTCHA"
    $not_increment = "HISTSIZE++"
  condition:
    any of ($h*) and none of ($not*)
}
