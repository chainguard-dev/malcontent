
rule pcap_shell_exec : suspicious {
  meta:
	description = "Sniffs network traffic, executes code through a shell"
  strings:
    $libpcap = "libpcap"

    $shell = "shell" fullword
	$sh = "/bin/sh"
	$sh_bash = "/bin/bash"

    $y_exec = "exec" fullword
    $y_execve = "execve" fullword
    $y_execvp = "execvp" fullword
	$y_system = "system"

	$not_airportd = "airportd"
  condition:
	$libpcap and any of ($sh*) and any of ($y*) and none of ($not*)
}
