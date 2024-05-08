
rule write_open_http : suspicious {
  meta:
    jumpcloud = "https://www.mandiant.com/resources/blog/north-korea-supply-chain"
    hash_2024_jumpcloud_init = "6acfc6f82f0fea6cc2484021e87fec5e47be1459e71201fbec09372236f8fc5a"
  strings:
    $write_open_https = ".write(open('https://"
    $write_open_http = ".write(open('http://"
  condition:
    any of them
}
