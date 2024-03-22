rule write_open_http : suspicious {
  meta:
    jumpcloud = "https://www.mandiant.com/resources/blog/north-korea-supply-chain"
    hash_2023_jumpcloud_init = "d4918e0b1883e12408aba9eb26071038a45fb020f1a489a2b2a36ab8b225f673"
  strings:
    $write_open_https = ".write(open('https://"
    $write_open_http = ".write(open('http://"
  condition:
    any of them
}


