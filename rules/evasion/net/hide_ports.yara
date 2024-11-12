private rule macho {
  condition:
    uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178
}

private rule elf {
  condition:
    uint32(0) == 1179403647
}

rule hides_ports: high {
  meta:
    description = "may hide ports"

  strings:
    $bin_ss        = "/usr/bin/ss"
    $bin_netstat   = "/usr/bin/netstat"
    $bin_readdir64 = "readdir64"
    $hideport      = "hideport"
    $hide_port     = "hide_port"
    $hidden_port   = "hidden_port"

  condition:
    filesize < 2MB and (macho or elf) and any of ($bin*) and any of ($hid*)
}
