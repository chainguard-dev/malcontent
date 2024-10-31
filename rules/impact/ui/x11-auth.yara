
rule x11_refs : notable {
  meta:
    description = "X Window System client authentication"
    ref = "https://en.wikipedia.org/wiki/X_Window_authorization"
    hash_2023_Linux_Malware_Samples_4259 = "4259f2da90bf344092abc071f376753adaf077e13aeed684a7a3c2950ec82f69"
    hash_2023_Linux_Malware_Samples_6de1 = "6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"
    hash_2023_Linux_Malware_Samples_d2ff = "d2fff992e40ce18ff81b9a92fa1cb93a56fb5a82c1cc428204552d8dfa1bc04f"
  strings:
    $cookie = "MIT-MAGIC-COOKIE-1" fullword
    $xauth = "xauth" fullword
  condition:
    any of them
}
