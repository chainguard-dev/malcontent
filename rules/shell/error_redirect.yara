rule error_redirect : notable {
	meta:
		description = "Runs shell commands but throws output away"
	strings:
		$bash = /> {0,2}\/dev\/null 2> {0,2}&1/
		$both = /> {0,2}\/dev\/null 2> {0,2}\/dev\/null/
	condition:
		any of them
}
