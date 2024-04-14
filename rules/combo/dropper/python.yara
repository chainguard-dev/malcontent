rule http_open_write_system : suspicious {
  meta:
  	description = "may fetch and execute programs from the internet"
  strings:
	$http = "http"
	$http_requests = "requests.get"
	$http_urrlib = "urllib.request"
	$http_urlopen = "urlopen"

	$open = "open("

	$write = "write("

	$system = "os.system("
	$sys_popen = "os.popen"
	$sys_sub = "subprocess."
  condition:
    filesize < 16384 and any of ($h*) and $open and $write and any of ($sys*)
}

rule setuptools_dropper : critical {
	meta:
		description = "setuptools script that downloads and executes content"
	strings:
		$setup = "setup("
		$setuptools = "setuptools"

		$http_requests = "requests.get"
		$http_urrlib = "urllib.request"
		$http_urlopen = "urlopen"

		$system = "os.system("
		$sys_popen = "os.popen"
		$sys_sub = "subprocess."

	condition:
		all of ($setup*) and any of ($http*) and any of ($sys*)
}