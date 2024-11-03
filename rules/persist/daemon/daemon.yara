rule daemon: medium {
  meta:
    description              = "Run as a background daemon"
    hash_2023_misc_mr_robot  = "630bbcf0643d9fc9840f2f54ea4ae1ea34dc94b91ee011779c8e8c91f733c9f5"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

  strings:
    $ref  = /[\w\-]{0,8}[dD]aemon/
    $ref2 = /[dD]aemonize/ fullword

  condition:
    filesize < 20MB and any of them
}
