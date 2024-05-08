
rule bash_persist : notable {
  meta:
    description = "access bash startup files"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0ca7 = "0ca7e0eddd11dfaefe0a0721673427dd441e29cf98064dd0f7b295eae416fe1b"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
  strings:
    $ref = ".bash_profile"
    $ref2 = ".profile" fullword
    $ref3 = ".bashrc" fullword
    $ref4 = ".bash_logout"
    $ref5 = "/etc/profile"
    $ref6 = "/etc/bashrc"
    $ref7 = "/etc/bash"
    $not_bash = "POSIXLY_CORRECT"
  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}

rule bash_logout_persist : suspicious {
  meta:
    description = "Writes to bash configuration files to persist"
  strings:
    $ref = ".bash_logout"
    $not_bash = "POSIXLY_CORRECT"
  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}
