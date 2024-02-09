rule bsd_sem_signal {
	strings:
		$semaphore_signal = "semaphore_signal" fullword
	condition:
		any of them
}