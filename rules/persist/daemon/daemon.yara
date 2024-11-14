rule daemon: medium {
  meta:
    description             = "Run as a background daemon"
    hash_2023_misc_mr_robot = "630bbcf0643d9fc9840f2f54ea4ae1ea34dc94b91ee011779c8e8c91f733c9f5"

  strings:
    $ref  = /[\w\-]{0,8}[dD]aemon/
    $ref2 = /[dD]aemonize/ fullword

  condition:
    filesize < 20MB and any of them
}
