
rule contains_base64 : notable {
  meta:
    description = "Contains base64 content"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_0xencbase = "50057362c139184abb74a6c4ec10700477dcefc8530cf356607737539845ca54"
    hash_2023_0xShell_wesobase = "17a1219bf38d953ed22bbddd5aaf1811b9380ad0535089e6721d755a00bddbd0"
  strings:
    $directory = "directory" base64
    $address = "address" base64
    $html = "html" base64
    $uname = "uname" base64
    $select = "select" base64
    $company = "company" base64
    $CERTIFICATE = "CERTIFICATE" base64
  condition:
    any of them
}

rule contains_base64_certificate : notable {
  meta:
    description = "Contains base64 CERTIFICATE"
    hash_2024_Downloads_e241 = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"
    hash_2017_MacOS_AppStore = "363d151d451a9687d5c0863933a15f7968d3d7018b26f6ba8df54dea9e2f635c"
    hash_2023_UPX_5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59_elf_x86_64 = "56ca5d07fa2e8004a008222a999a97a6c27054b510e8dd6bd22048b084079e37"
  strings:
    $CERTIFICATE = "CERTIFICATE" base64
  condition:
    any of them
}
