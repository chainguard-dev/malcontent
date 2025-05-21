include "rules/global/global.yara"

rule hides_ports: high {
  meta:
    description = "may hide ports"
    filetypes   = "elf,macho"

  strings:
    $bin_ss        = "/usr/bin/ss"
    $bin_netstat   = "/usr/bin/netstat"
    $bin_readdir64 = "readdir64"
    $hideport      = "hideport"
    $hide_port     = "hide_port"
    $hidden_port   = "hidden_port"

  condition:
    filesize < 2MB and (global_elf_or_macho) and any of ($bin*) and any of ($hid*)
}
