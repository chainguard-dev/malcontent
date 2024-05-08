
rule home_path : notable {
  meta:
    description = "references path within /home"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
  strings:
    $home = /\/home\/[%\w\.\-\/]{0,64}/
    $not_build = "/home/build"
    $not_runner = "/home/runner"
  condition:
    $home and none of ($not*)
}
