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

  // "/dev/udp" is a substring of $not_echo, so a script containing the benign
  // echo probe had every other /dev/udp use in it suppressed. Compare
  // occurrence counts for that one; the other two carry no /dev/udp of their
  // own and stay presence-based.

  condition:
    filesize < 1KB and $ref and #ref > #not_echo and none of ($not_posixly_correct, $not_dd)
}
