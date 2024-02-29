rule rootkit : suspicious {
	meta:
		description = "References a rootkit"
	strings:
		$s_Rootkit = "Rootkit"
		$s_r00tkit = "r00tkit"
		$s_r00tk1t = "r00tk1t"
	    $s_rootkit = "rootkit"
	condition:
		any of them
}