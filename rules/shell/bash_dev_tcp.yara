
rule bash_dev_tcp : suspicious exfil {
  meta:
	description = "uses /dev/tcp for network access (bash)"
  strings:
    $ref = "/dev/tcp"
    $posixly_correct = "POSIXLY_CORRECT"
  condition:
    $ref and not $posixly_correct
}
