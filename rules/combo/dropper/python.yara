private rule py_fetcher {
	meta:
		description = "fetches content"
	strings:
		$http_requests = "requests.get" fullword
		$http_requests_post = "requests.post" fullword
		$http_urrlib = "urllib.request" fullword
		$http_urlopen = "urlopen" fullword
	condition:
		any of ($http*)
}

private rule py_runner {
	meta:
		description = "runs programs"
	strings:
		$os_system = /os.system\([\"\'\w\ \-\)\/]{0,64}/
		$os_popen = /os.spopen\([\"\'\w\ \-\)\/]{0,64}/
		$subprocess = /subprocess.\w{0,32}\([\"\'\/\w\ \-\)]{0,64}/
	condition:
		any of them
}

rule py_dropper : suspicious {
  meta:
  	description = "fetch, stores, and execute programs"
  strings:
	$open = "open("
	$write = "write("
  condition:
    filesize < 16384 and $open and $write and py_fetcher and py_runner
}

private rule pythonSetup {
	strings:
		$i_distutils = "from distutils.core import setup"
		$i_setuptools = "setuptools"
		$setup = "setup("
	condition:
		filesize < 2MB and $setup and any of ($i*)
}

rule setuptools_fetcher : suspicious {
	meta:
		description = "setuptools script that fetches content"
	condition:
		pythonSetup and py_fetcher
}

rule setuptools_fetch_run : critical {
	meta:
		description = "setuptools script that fetches and executes"
	condition:
		setuptools_fetcher and py_runner
}

rule setuptools_dropper : critical {
	meta:
		description = "setuptools script that fetches, stores, and executes"
	condition:
		pythonSetup and py_dropper
}
