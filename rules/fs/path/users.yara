rule home_path: medium {
  meta:
    description = "references path within /Users"

    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_016a  = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"

  strings:
    $ref = /\/Users\/[\$\(\)%\w\.\-\/]{0,64}/

  condition:
    $ref
}
