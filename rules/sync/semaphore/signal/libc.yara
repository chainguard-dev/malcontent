rule bsd {
	strings:
		$semaphore_signal = "semaphore_signal" fullword
	condition:
		any of them
}