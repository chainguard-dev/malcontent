
rule executable_calls_archive_tool : suspicious {
  meta:
    description = "command shells out to tar"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
  strings:
    $a_tar_c = "tar -c"
    $a_tar_rX = "tar -r -X"
    $a_tar_T = "tar -T"
    $hash_bang = "#!"
  condition:
    any of ($a*) and not $hash_bang in (0..2)
}
