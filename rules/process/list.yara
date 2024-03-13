
rule proc_listallpids : notable {
	meta:
		pledge = "exec"
		syscall = "vfork"
	strings:
		$ref = "proc_listallpid" fullword
	condition:
		any of them
}

rule ps_exec : notable {
  meta:
	pledge = "exec"
	syscall = "vfork"
  strings:
    $ps_ef = "ps -ef |"
    $ps__ax = "ps -ax"
	$ps_ax = "ps ax"
    $hash_bang = "#!"
    $not_node = "NODE_DEBUG_NATIVE"
    $not_apple = "com.apple."
  condition:
    any of ($ps*) and not $hash_bang in (0..2) and none of ($not*)
}

rule procfs_listdir : notable {
	meta:
		pledge = "exec"
		syscall = "vfork"
	strings:
		$shell = "ls /proc" fullword
		$python = "os.listdir('/proc')"
	condition:
		any of them
}


rule proclist : high {
	meta:
		description = "accesses process list"
	strings:
		$proclist = "proclist" fullword
	condition:
		any of them
}