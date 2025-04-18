rule chmod: medium {
  meta:
    description = "modifies file permissions"
    pledge      = "fattr"
    syscall     = "chmod"
    ref         = "https://linux.die.net/man/1/chmod"

  strings:
    $chmod    = "chmod" fullword
    $dotChmod = "Chmod" fullword
    $_setmode = "_setmode" fullword

  condition:
    any of them
}

rule fchmod: notamble {
  meta:
    description = "modifies file permissions"
    pledge      = "fattr"
    syscall     = "fchmodat"
    ref         = "https://linux.die.net/man/2/fchmodat"

  strings:
    $fchmod    = "fchmod" fullword
    $dotfchmod = ".Fchmod" fullword
    $fchmodat  = "fchmodat" fullword

  condition:
    any of them
}

rule chmod_word_writeable: medium {
  meta:
    description = "Makes a world writeable file"

  strings:
    $ref  = /chmod [\-\w ]{0,4}666[ \$\w\/\.]{0,32}/
    $ruby = "chmod(0666)"

  condition:
    filesize < 50MB and any of ($r*)
}

rule chmod_dangerous_exec: high exfil {
  meta:
    description = "Makes path world writeable and executable"

  strings:
    $ref             = /chmod [\-\w ]{0,4}777[ \$\w\/\.]{0,32}/
    $ruby            = "chmod(0777)"
    $r_python        = /chmod\([\w, ]{1,16}777\)/
    $not_chmod_1777  = "chmod 1777"
    $not_chmod_01777 = "chmod 01777"
    $not_chromium    = "CHROMIUM_TIMESTAMP"
    $not_var_tmp     = "chmod 0777 /var/tmp" fullword
    $not_extutils    = "chmod 0777, [.foo.bar] doesn't work on VMS"
    $not_sonarqube   = "Setting loose POSIX file permissions is security-sensitive"

  condition:
    filesize < 50MB and any of ($r*) and none of ($not*)
}

rule chmod_group_writeable: high exfil {
  meta:
    description = "Makes path group writeable and executable"

  strings:
    $ref             = /chmod [\-\w ]{0,4}770[ \$\w\/\.]{0,32}/
    $r_python        = /chmod\([\w, ]{1,16}770\)/
    $ruby            = "chmod(0770)"
    $not_chmod_1777  = "chmod 1770"
    $not_chmod_01777 = "chmod 01770"
    $not_chromium    = "CHROMIUM_TIMESTAMP"
    $not_var_tmp     = "chmod 0770 /var/tmp" fullword
    $not_extutils    = "chmod 0770, [.foo.bar] doesn't work on VMS"
    $not_sonarqube   = "Setting loose POSIX file permissions is security-sensitive"

  condition:
    filesize < 50MB and any of ($r*) and none of ($not*)
}
