rule var_log_path: medium {
  meta:
    description              = "path reference within /var/log"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

  strings:
    $ref = /\/var\/log\/[\%\w\.\-\/]{4,32}/ fullword

  condition:
    $ref
}
