
rule crypto_ssh : notable {
	meta:
		description = "Uses crypto/ssh to connect to the SSH (secure shell) service"
	strings:
		$go = "crypto/ssh" fullword
	condition:
		any of them
}