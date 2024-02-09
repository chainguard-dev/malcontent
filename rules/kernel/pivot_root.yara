rule pivot_root {
	meta:
		capability = "CAP_SYS_SYSADMIN"
		description = "change the root mount location"
		syscall = "pivot_root"
	strings:
		$ref = "pivot_root" fullword
	condition:
		any of them
}