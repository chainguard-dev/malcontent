rule pthreads : harmless {
	meta:
		description = "Uses pthreads"
	strings:
		$init = "pthread_cond_init" fullword
		$wait = "pthread_cond_wait" fullword
		$join = "pthread_join" fullword
	condition:
		any of them
}