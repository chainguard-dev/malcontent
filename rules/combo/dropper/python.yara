rule http_open_write_system : suspicious {
  meta:
  	description = "may fetch and execute programs from the internet"
  strings:
	$http = "http"
	$http_requests = "requests.get" fullword
	$http_urrlib = "urllib.request" fullword
	$http_urlopen = "urlopen" fullword

	$open = "open("

	$write = "write("

	$system = "os.system" fullword
	$sys_popen = "os.popen" fullword
	$sys_sub = "subprocess" fullword
  condition:
    filesize < 16384 and any of ($h*) and $open and $write and any of ($sys*)
}

rule setuptools_dropper : critical {
	meta:
		description = "setuptools script that downloads and executes content"
	strings:
		$setup = "setup("
		$setuptools = "setuptools" fullword

		$http_requests = "requests.get" fullword
		$http_urrlib = "urllib.request" fullword
		$http_urlopen = "urlopen" fullword

		$system = "os.system" fullword
		$sys_popen = "os.popen" fullword
		$sys_sub = "subprocess" fullword

	condition:
		all of ($setup*) and any of ($http*) and any of ($sys*)
}