
rule executable_calls_archive_tool : high {
  meta:
    description = "command shells out to tar"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_AtomicStealer_Trading_View = "ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a"
    hash_2021_CDDS_UserAgent_v2019 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
  strings:
    $a_tar_c = "tar -c"
    $a_tar_rX = "tar -r -X"
    $a_tar_T = "tar -T"
    $hash_bang = "#!"
  condition:
    any of ($a*) and not $hash_bang in (0..2)
}
