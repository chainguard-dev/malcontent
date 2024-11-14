rule netstat: medium {
  meta:
    description = "Uses 'netstat' for network information"

  strings:
    $ref1 = /netstat[ \-a-z\|]{0,16}/

  condition:
    all of them
}
