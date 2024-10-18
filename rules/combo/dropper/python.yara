private rule py_fetcher {
	meta:
		description = "fetches content"
	strings:
		$http_requests = "requests.get" fullword
		$http_requests_post = "requests.post" fullword
		$http_urrlib = "urllib.request" fullword
		$http_urlopen = "urlopen" fullword

		$http_curl = "curl" fullword
		$http_wget = "wget" fullword
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

rule py_dropper : medium {
  meta:
  	description = "may fetch, stores, and execute programs"
  strings:
	$open = "open("
	$write = "write("
  condition:
    filesize < 16384 and $open and $write and py_fetcher and py_runner
}

rule py_dropper_chmod : high {
  meta:
  	description = "fetch, stores, chmods, and execute programs"
  strings:
	$chmod = "chmod"
	$val_x = "+x"
	$val_exec = "755"
	$val_rwx = "777"
  condition:
    filesize < 16384 and py_fetcher and py_runner and $chmod and any of ($val*)
}

private rule pythonSetup {
  strings:
    $i_distutils = "from distutils.core import setup"
    $i_setuptools = "from setuptools import setup"
	$setup = "setup("

	$not_setup_example = ">>> setup("
	$not_setup_todict = "setup(**config.todict()"
	$not_import_quoted = "\"from setuptools import setup"
	$not_setup_quoted = "\"setup(name="
	$not_distutils = "from distutils.errors import"
	$not_dir = "dist-packages/setuptools"
	$not_fetch = "fetch_distribution"
  condition:
    filesize < 128KB and $setup and any of ($i*) and none of ($not*)
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

rule dropper_imports : high {
	meta:
		description = "imports modules known to be used by Python droppers"
		filetypes = "python"
	strings:
		$http = "http"
		$import = "import" fullword
		$l_base64 = "base64" fullword
		$l_platform = "platform" fullword
		$l_os = "os" fullword
		$l_subprocess = "subprocess" fullword
		$l_sys = "sys" fullword
		$l_requests = "requests" fullword
	condition:
		filesize < 4000 and $http and $import and 5 of ($l*)
}
