
rule executable_calls_archive_tool : high {
  meta:
    description = "command shells out to tar"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
  strings:
    $a_tar_c = "tar -c"
    $a_tar_rX = "tar -r -X"
    $a_tar_T = "tar -T"
    $hash_bang = "#!"
  condition:
    any of ($a*) and not $hash_bang in (0..2)
}
