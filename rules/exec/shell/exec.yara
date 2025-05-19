rule calls_shell: medium {
  meta:
    description = "executes shell"

  strings:
    $bin_sh          = "/bin/sh"
    $bin_bash        = "/bin/bash"
    $bin_dash        = "/bin/dash"
    $bin_zsh         = "/bin/zsh"
    $sh_val          = /\/bin\/sh[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
    $bash_val        = /\/bin\/bash[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
    $dash_val        = /\/bin\/dash[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
    $zsh_val         = /\/bin\/zsh[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
    $bash_apostrophe = "'bash'"

  condition:
    filesize < 104857600 and any of them
}

rule ExecShell: medium {
  meta:
    description = "executes a shell"

  strings:
    $ExecShell    = "ExecShell" fullword
    $ExecuteShell = "ExecuteShell" fullword
    $exec_shell   = "exec_shell" fullword
    $execShell    = "execShell" fullword
    $executeShell = "executeShell" fullword
    $RunShell     = "RunShell" fullword
    $runShell     = "runShell" fullword
    $run_shell    = "run_shell" fullword
    $runshell     = "runshell" fullword

  condition:
    any of them
}

rule system_call: medium {
  meta:
    description = "executes a shell command"
    filetypes   = "elf"

  strings:
    $ref = "system" fullword

  condition:
    uint32(0) == 1179403647 and $ref in (1024..3000)
}

rule macho_system: medium {
  meta:
    description = "executes a shell command"
    filetypes   = "macho"

  strings:
    $ref = "@_system" fullword

  condition:
    (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178) and $ref

}
