rule ssh_attack: high {
  meta:
    description = "references an 'SSH Attack'"

  strings:
    $sshAttack  = /[a-zA-Z\-_ ]{0,16}sshAttack[a-zA-Z\-_ ]{0,16}/ fullword
    $ssh_attack = /[a-zA-Z\-_ ]{0,16}ssh_attack[a-zA-Z\-_ ]{0,16}/ fullword
    $attackSSH  = /[a-zA-Z\-_ ]{0,16}attackSSH[a-zA-Z\-_ ]{0,16}/ fullword
    $attackSsh  = /[a-zA-Z\-_ ]{0,16}attackSsh[a-zA-Z\-_ ]{0,16}/ fullword
    $attack_ssh = /[a-zA-Z\-_ ]{0,16}attack_ssh[a-zA-Z\-_ ]{0,16}/ fullword
    $ssh_boom   = /[a-zA-Z\-_ ]{0,16}ssh_boom[a-zA-Z\-_ ]{0,16}/ fullword

  condition:
    any of them
}
