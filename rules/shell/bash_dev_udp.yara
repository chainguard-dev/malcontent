
rule bash_dev_udp : high exfil {
  meta:
	description = "uses /dev/udp for network access (bash)"
  strings:
    $ref = "/dev/udp"
    $posixly_correct = "POSIXLY_CORRECT"
  condition:
    $ref and not $posixly_correct
}
