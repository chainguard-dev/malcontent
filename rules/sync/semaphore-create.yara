rule bsd {
	strings:
		$semaphore_create = "semaphore_create" fullword
	condition:
		any of them
}