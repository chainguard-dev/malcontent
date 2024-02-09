rule bsd_sem_create {
	strings:
		$semaphore_create = "semaphore_create" fullword
	condition:
		any of them
}