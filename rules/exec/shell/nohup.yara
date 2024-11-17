rule nohup_reference_value: medium {
  meta:
    description = "Runs command that is protected from termination"

  strings:
    $nohup         = "nohup" fullword
    $nohup_re_val  = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_append    = "appending output"
    $not_usage     = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd     = "pushd"

  condition:
    filesize < 52428800 and any of ($nohup*) and none of ($not*)
}

rule elf_nohup: high {
  meta:
    description = "Runs command that is protected from termination"

  strings:
    $nohup         = "nohup" fullword
    $nohup_re_val  = /nohup[ \%\{\}\$\-\w\"\']{2,64}/
    $not_append    = "appending output"
    $not_usage     = "usage: nohup"
    $not_nohup_out = "nohup.out"
    $not_pushd     = "pushd"

  condition:
    uint32(0) == 1179403647 and filesize < 1MB and any of ($nohup*) and none of ($not*)
}

rule nohup_bash: high {
  meta:
    description = "Calls bash with nohup"

  strings:
    $ref = /nohup bash[ \w\/\&\.\-\%\\>]{0,32}/

  condition:
    any of them
}
