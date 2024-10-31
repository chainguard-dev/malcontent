
rule ssh_authorized_hosts : medium {
  meta:
    description = "accesses SSH authorized_keys files"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_6de1 = "6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"
    hash_2023_Linux_Malware_Samples_d2ff = "d2fff992e40ce18ff81b9a92fa1cb93a56fb5a82c1cc428204552d8dfa1bc04f"
  strings:
    $ref = ".ssh"
    $authorized_hosts = /[\/\.\$\%]{0,32}authorized_keys/
  condition:
    all of them
}
