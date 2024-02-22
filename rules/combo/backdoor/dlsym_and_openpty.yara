
rule dlsym_openpty_system : suspicious {
	meta:
		description = "Resolves library, opens terminal, calls shell"
	strings:
		$dlsym = "dlsym" fullword
		$openpty = "openpty" fullword
		$system = "system"
	condition:
		all of them in (1200..3000)
}
