rule contains_base64_url: medium {
  meta:
    description = "Contains base64 url"


    hash_2023_0xShell_wesobase  = "17a1219bf38d953ed22bbddd5aaf1811b9380ad0535089e6721d755a00bddbd0"

  strings:
    $http  = "http://" base64
    $https = "https://" base64
    $tcp   = "tcp://" base64
    $udp   = "udp://" base64
    $ftp   = "ftp://" base64

  condition:
    any of them
}
