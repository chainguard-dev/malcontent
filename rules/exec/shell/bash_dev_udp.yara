rule bash_dev_udp: medium exfil {
  meta:
    description = "uses /dev/udp for network access (bash)"

  strings:
    $ref = "/dev/udp"

  condition:
    $ref
}

rule bash_dev_udp_high: high exfil {
  meta:
    description = "uses /dev/udp for network access (bash)"

  strings:
    $ref                 = "/dev/udp"
    $not_posixly_correct = "POSIXLY_CORRECT"
    $not_dd              = "dd if=/dev/zero"
    $not_echo            = "echo > /dev/udp"

  condition:
    filesize < 1KB and $ref and none of ($not*)
}
