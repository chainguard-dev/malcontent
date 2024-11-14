rule htpasswd: medium {
  meta:
    description = "Access .htpasswd files"

    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"

  strings:
    $ref  = ".htpasswd"
    $ref2 = "Htpasswd"

  condition:
    any of them
}
