rule process_injector_value : critical {
	meta:
		description = "may inject code into other processes"
	strings:
		$maps = "proc/%d/maps"
		$maps2 = "proc/%s/maps"
		$maps_file = "maps file"
		$memory_region = "memory_region"

		$injection = "inject"
		$injected = "Inject"

		$ptrace = "trace" fullword
		$proc = "process" fullword

		$not_qemu = "QEMU_IS_ALIGNED"
	condition:
		any of ($m*) and any of ($i*) and any of ($p*) and none of ($not*)
}
