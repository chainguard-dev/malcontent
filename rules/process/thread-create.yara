rule pthread_create : notable {
	meta:
		syscall = "pthread_create"
		description = "create a new thread"
		ref = "https://man7.org/linux/man-pages/man3/pthread_create.3.html"
	strings:
		$ref = "pthread_create" fullword
	condition:
		any of them
}