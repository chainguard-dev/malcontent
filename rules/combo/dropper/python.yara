rule http_open_write_system : suspicious {
  strings:
	$http = "http"
	$h_rget = "requests.get"

	$open = "open("

	$write = "write("

	$system = "os.system("
	$sys_popen = "os.popen"
  condition:
    filesize < 16384 and any of ($h*) and $open and $write and any of ($sys*)
}

rule setuptools_dropper : critical {
	meta:
		description = "setuptools script that downloads and executes content"
	strings:
		$setup = "setup("
		$setuptools = "setuptools"
		$requests = "requests.get"
		$os_sys = "os.system"
	condition:
		all of them
}