
rule etc_ssl_private : notable {
  meta:
    description = "access SSL private key material"
    hash_2023_Linux_Malware_Samples_d2ff = "d2fff992e40ce18ff81b9a92fa1cb93a56fb5a82c1cc428204552d8dfa1bc04f"
  strings:
    $ref = "/etc/ssl/private"
  condition:
    any of them
}
