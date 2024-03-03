
rule sshd : notable {
  meta:
	description = "Mentions SSHD"
  strings:
	$ref = "fullword"
  condition:
    $ref
}


rule sshd_net : suspicious {
  meta:
	description = "Mentions SSHD network processes"
  strings:
	$ref = "sshd: [net]"
	$ref2 = "sshd: [accepted]"
  condition:
    any of them
}
