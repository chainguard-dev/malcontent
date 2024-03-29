rule rootkit_up : suspicious {
	meta:
		description = "references a 'rootkit'"
	strings:
		$s_Rootkit = "Rootkit"
		$s_r00tkit = "r00tkit"
		$s_r00tk1t = "r00tk1t"
	condition:
		any of them
}

rule rootkit : notable {
	meta:
		description = "references a 'rootkit'"
	strings:
	    $s_rootkit = "rootkit" fullword
	condition:
		any of them
}