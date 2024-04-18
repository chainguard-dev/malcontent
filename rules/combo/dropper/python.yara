rule http_open_write_system : suspicious {
  meta:
  	description = "fetch and execute programs"
  strings:
	$http_requests_get = "requests.get" fullword
	$http_requests_post = "requests.post" fullword
	$http_urllib = "urllib.request" fullword
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
		description = "setuptools script that fetches and executes"
	strings:
		$setup = "setup("
		$setuptools = "setuptools" fullword

		$http_requests = "requests.get" fullword
		$http_requests_post = "requests.post" fullword
		$http_urrlib = "urllib.request" fullword
		$http_urlopen = "urlopen" fullword

		$system = "os.system" fullword
		$sys_popen = "os.popen" fullword
		$sys_sub = "subprocess" fullword

	condition:
		all of ($setup*) and any of ($http*) and any of ($sys*)
}