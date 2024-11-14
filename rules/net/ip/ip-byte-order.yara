rule htonl: medium {
  meta:
    pledge      = "inet"
    description = "convert values between host and network byte order"

    hash_2023_Linux_Malware_Samples_123e = "123e6d1138bfd58de1173818d82b504ef928d5a3be7756dd627c594de4aad096"
    hash_2023_Linux_Malware_Samples_2bc8 = "2bc860efee229662a3c55dcf6e50d6142b3eec99c606faa1210f24541cad12f5"

  strings:
    $ref  = "htonl" fullword
    $ref2 = "htons" fullword

  condition:
    any of them in (1300..3000)
}
