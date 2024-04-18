rule process_injector_value : high {
	meta:
		description = "may inject code into other processes"
	strings:
		$maps = "proc/%d/maps"
		$maps2 = "proc/%s/maps"
		$maps_file = "maps file"
		$memory_region = "memory_region"

		$injection = /[a-zA-Z\- ]{0,16}inject[a-zA-Z\- ]{0,16}/
		$injected = /[a-zA-Z\- ]{0,16}Inject[a-zA-Z\- ]{0,16}/

		$ptrace = "trace" fullword
		$proc = "process" fullword

		$not_qemu = "QEMU_IS_ALIGNED"
		$not_fault_inject = "fault_injection"
	condition:
		filesize < 64MB and any of ($m*) and any of ($i*) and any of ($p*) and none of ($not*)
}
