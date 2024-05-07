import "math"

rule setuptools_cmd_exec : suspicious {
	meta:
		description = "Python library installer that executes external commands"
	strings:
		$setup = "setup(" fullword

		$setuptools = "setuptools"
		$distutils = "distutils"

		$s_sys_val = /os.system\([\"\'\w\ \-\)\/]{0,64}/
		$s_subprocess_val = /subprocess.\w{0,32}\([\"\'\/\w\ \-\)]{0,64}/
		$s_import = "import subprocess"
	condition:
		$setup and ($setuptools or $distutils) and any of ($s_*)
}

rule setuptools_eval : critical {
	meta:
		description = "Python library installer that evaluates arbitrary code"
	strings:
		$setup = "setup(" fullword

		$setuptools = "setuptools"
		$distutils = "distutils"

		$s_sys_val = /eval\([\"\'\w\ \-\)\/]{0,64}/ fullword
		$s_subprocess_val = /exec\([\"\'\/\w\ \-\)]{0,64}/ fullword
	condition:
		$setup and ($setuptools or $distutils) and any of ($s_*)
}

rule setuptools_url_access : suspicious {
	meta:
		description = "Python library installer that accesses external URLs"
	strings:
		$setup = "setup(" fullword

		$setuptools = "setuptools"
		$distutils = "distutils"

		$s_requests = /requests.get\([\"\'\w\ \-\)\/]{0,64}/
		$s_urlopen = /urlopen\([\"\'\w\ \-\)\/]{0,64}/
	condition:
		$setup and ($setuptools or $distutils) and any of ($s_*)
}

rule setuptools_random : critical {
	meta:
		description = "Python library installer that exhibits random behavior"
	strings:
		$setup = "setup(" fullword

		$setuptools = "setuptools"
		$distutils = "distutils"

		$s_sys_val = "import random" fullword
	condition:
		$setup and ($setuptools or $distutils) and any of ($s_*)
}

rule setuptools_builtins : notable {
	meta:
		description = "Python library installer that directly references builtins"
	strings:
		$setup = "setup(" fullword

		$setuptools = "setuptools"
		$distutils = "distutils"

		$s_sys_val = "__builtins__" fullword
	condition:
		$setup and ($setuptools or $distutils) and any of ($s_*)
}