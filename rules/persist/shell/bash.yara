rule bash_persist: medium {
  meta:
    description = "access bash startup files"

  strings:
    $ref      = ".bash_profile"
    $ref2     = ".profile" fullword
    $ref3     = ".bashrc" fullword
    $ref4     = ".bash_logout"
    $ref5     = "/etc/profile"
    $ref6     = "/etc/bashrc"
    $ref7     = "/etc/bash"
    $not_bash = "POSIXLY_CORRECT"

  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}

rule bash_persist_persistent: high {
  meta:
    description = "acccesses multiple bash startup files"

  strings:
    $ref1 = ".bash_profile"
    $ref2 = ".bash_login"
    $ref3 = ".profile"
    $ref4 = ".bashrc"

    $not_bash   = "POSIXLY_CORRECT"
    $not_csh    = ".cshrc"
    $not_tcsh   = "tcsh" fullword
    $not_tcshrc = ".tcshrc"

  condition:
    3 of them and none of ($not*)

}

rule hardcoded_bash_persist_file: high {
  meta:
    description = "hardcodes a shell startup file"

  strings:
    $profile = /\/[\w\.\/]{0,32}\/\.profile/ fullword
    $bashrc  = /\/[\w\.\/]{0,32}\/\.bashrc/ fullword

  condition:
    filesize < 100MB and uint32(0) == 1179403647 and any of them
}

rule bash_logout_persist: high {
  meta:
    description = "Writes to bash configuration files to persist"

  strings:
    $ref         = ".bash_logout"
    $not_bash    = "POSIXLY_CORRECT"
    $not_comment = "# ~/.bash_logout"
    $not_clear   = "/usr/bin/clear_console"
    $not_csh     = ".cshrc"
    $not_tcshrc  = ".tcshrc"

  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}
