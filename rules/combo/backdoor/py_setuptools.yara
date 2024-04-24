import "math"

private rule pySetupScript {
	strings:
		$import = "from distutils.core import setup"
		$setup = "setup(" fullword
	condition:
		all of them
}

rule setuptools_cmd_exec : suspicious {
	meta:
		description = "Python library installer that executes external commands"
	strings:
		$f_sys_val = /os.system\([\"\'\w\ \-\)\/]{0,64}/
		$f_subprocess_val = /subprocess.\w{0,32}\([\"\'\/\w\ \-\)]{0,64}/
		$f_import = "import subprocess"
	condition:
		pySetupScript and any of ($f*)
}

rule setuptools_eval : critical {
	meta:
		description = "Python library installer that evaluates arbitrary code"
	strings:
		$f_sys_val = /eval\([\"\'\w\ \-\)\/]{0,64}/ fullword
		$f_subprocess_val = /exec\([\"\'\/\w\ \-\)]{0,64}/ fullword
	condition:
		pySetupScript and any of ($f*)
}

rule setuptools_url_access : suspicious {
	meta:
		description = "Python library installer that accesses external URLs"
	strings:
		$f_requests = /requests.get\([\"\'\w\ \-\)\/]{0,64}/
		$f_urlopen = /urlopen\([\"\'\w\ \-\)\/]{0,64}/
	condition:
		pySetupScript and any of ($f_*)
}

rule setuptools_random : critical {
	meta:
		description = "Python library installer that exhibits random behavior"
	strings:
		$f_sys_val = "import random" fullword
	condition:
		pySetupScript and any of ($f_*)
}

rule setuptools_builtins : notable {
	meta:
		description = "Python library installer that directly references builtins"
	strings:
		$f_sys_val = "__builtins__" fullword
	condition:
		pySetupScript and any of ($f_*)
}

rule setuptools_os_path_exists : notable {
	meta:
		description = "Python library installer that checks for file existence"
	strings:
		$f_urlopen = /os.path.exists\([\"\'\w\ \-\)\/]{0,32}/
	condition:
		pySetupScript and any of ($f_*)
}