rule bsd {
	strings:
		$semaphore_wait = "semaphore_wait" fullword
	condition:
		any of them
}