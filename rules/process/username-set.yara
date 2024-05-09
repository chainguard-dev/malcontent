
rule setlogin : medium {
  meta:
    syscall = "setlogin"
    description = "set login name"
    pledge = "id"
    hash_2023_Linux_Malware_Samples_47a4 = "47a4ca5b1b6a2c0c7914b342f668b860041ec826d2ac85825389dba363797431"
    hash_2023_Linux_Malware_Samples_6de1 = "6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"
    hash_2023_Linux_Malware_Samples_9a7e = "9a7e8ed9621c08964bd20eb8a95fbe9853e12ebc613c37f53774b17a2cbe9100"
  strings:
    $ref = "setlogin" fullword
  condition:
    any of them
}
