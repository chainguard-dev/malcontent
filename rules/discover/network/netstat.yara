rule netstat: medium {
  meta:
    description = "Uses 'netstat' for network information"

    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

  strings:
    $ref1 = /netstat[ \-a-z\|]{0,16}/

  condition:
    all of them
}
