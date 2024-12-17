rule zsh_persist: medium {
  meta:
    description = "access zsh startup files"

  strings:
    $ref      = ".zprofile"
    $ref2     = ".zshrc"
    $ref3     = "/etc/zprofile"
    $ref4     = "/etc/zshrc"
    $not_bash = "POSIXLY_CORRECT"

  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}

rule hardcoded_zsh_persist_file: high {
  meta:
    description = "hardcodes a shell startup file"

  strings:
    $zshenv = /\/[\w\.\/]{0,32}\/\.zshenv/ fullword
    $zshrc  = /\/[\w\.\/]{0,32}\/\.zshrc/ fullword

  condition:
    filesize < 100MB and uint32(0) == 1179403647 and any of them
}

rule zsh_logout_persist: high {
  meta:
    description = "Writes to zsh configuration files to persist"

  strings:
    $ref       = ".zlogout"
    $ref2      = "/etc/zlogout"
    $not_cshrc = ".cshrc"
    $not_zsh   = "ZSH_DEBUG_CMD"

  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}
