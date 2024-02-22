
rule ssh_socks5_exec : suspicious {
	meta:
		description = "Supports SOCKS5, SSH, and executing programs"
	strings:
		$socks5 = "Socks5"
		$ssh = "crypto/ssh"
		$exec = "os/exec.Command"
	condition:
		all of them
}
