
rule url_encode : medium {
  meta:
    description = "encodes URL, likely to pass GET variables"
    hash_2023_0xShell_adminer = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2017_package_package_setup = "79be89b218ac2160d6047c22a1161a2be048044f24e920872715e130496aec8c"
  strings:
    $ref = "urlencode"
  condition:
    any of them
}
