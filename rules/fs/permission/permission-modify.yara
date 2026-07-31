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
    $not_var_tmp     = "chmod 0777 /var/tmp"
    $not_extutils    = "chmod 0777, [.foo.bar] doesn't work on VMS"
    $not_sonarqube   = "Setting loose POSIX file permissions is security-sensitive"

  condition:
    // The four chmod exclusions are spellings $ref itself matches (its
    // [\-\w ]{0,4} run swallows the 1777/01777/0777 variants), so counting them
    // off leaves any additional chmod 777 site visible instead of silencing the
    // whole file. The remaining two are unrelated build/scanner markers.
    filesize < 50MB and any of ($r*) and
    #ref + #ruby + #r_python > #not_chmod_1777 + #not_chmod_01777 + #not_var_tmp + #not_extutils and
    none of ($not_chromium, $not_sonarqube)
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
    $not_var_tmp     = "chmod 0770 /var/tmp"
    $not_extutils    = "chmod 0770, [.foo.bar] doesn't work on VMS"
    $not_sonarqube   = "Setting loose POSIX file permissions is security-sensitive"

  condition:
    // Same shape as chmod_dangerous_exec: the four chmod exclusions are
    // spellings $ref already matches, so count them off rather than letting one
    // benign chmod 770 line silence every other one in the file.
    filesize < 50MB and any of ($r*) and
    #ref + #r_python + #ruby > #not_chmod_1777 + #not_chmod_01777 + #not_var_tmp + #not_extutils and
    none of ($not_chromium, $not_sonarqube)
}
