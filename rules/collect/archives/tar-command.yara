rule tar_script: medium {
  meta:
    description = "script shells out to tar"

  strings:
    $a_tar_rX  = /tar -r -X[\|\-\\\"\$\w\; ]{0,64}/
    $a_tar_T   = /tar -T[\|\-\\\"\$\w\; ]{0,64}/
    $hash_bang = "#!"

  condition:
    any of ($a*) and $hash_bang in (0..2)
}

rule local_tar: medium {
  meta:
    description               = "command archives current directory"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"

  strings:
    $a_tar_c = /tar -c\w{0,8} \. [\|\-\\\"\$\w\; ]{0,64}/

  condition:
    any of ($a*)
}

rule executable_calls_archive_tool: high {
  meta:
    description               = "command shells out to tar"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"

  strings:
    $a_tar_c   = /tar -c\w{0,8} \. [\|\-\\\"\$\w\; ]{0,64}/
    $a_tar_T   = /tar -T[\|\-\\\"\$\w\; ]{0,64}/
    $a_tar_rX  = /tar -r -X[\|\-\\\"\$\w\; ]{0,64}/
    $hash_bang = "#!"

  condition:
    any of ($a*) and not $hash_bang in (0..2) and not tar_script and not local_tar
}
