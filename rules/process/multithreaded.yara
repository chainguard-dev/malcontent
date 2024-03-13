rule pthread_create : notable {
	meta:
		syscall = "pthread_create"
		description = "uses pthreads"
		ref = "https://man7.org/linux/man-pages/man3/pthread_create.3.html"
	strings:
		$ref = "pthread_create" fullword
	condition:
		any of them
}

rule py_thread_create : notable {
	meta:
		syscall = "pthread_create"
		description = "uses python threading"
	strings:
		$ref = "threading.Thread"
	condition:
		any of them
}
