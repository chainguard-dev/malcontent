rule contains_base64: medium {
  meta:
    description = "Contains base64 content"


    hash_2023_0xShell_wesobase  = "17a1219bf38d953ed22bbddd5aaf1811b9380ad0535089e6721d755a00bddbd0"

  strings:
    $directory   = "directory" base64
    $address     = "address" base64
    $html        = "html" base64
    $uname       = "uname" base64
    $select      = "select" base64
    $company     = "company" base64
    $CERTIFICATE = "CERTIFICATE" base64

  condition:
    any of them
}

rule contains_base64_certificate: medium {
  meta:
    description              = "Contains base64 CERTIFICATE"



  strings:
    $CERTIFICATE = "CERTIFICATE" base64

  condition:
    any of them
}
