import "math"

rule pythonSetup {
	strings:
		$i_distutils = "from distutils.core import setup"
		$i_setuptools = "setuptools"
		$setup = "setup("
	condition:
		filesize < 32768 and $setup and any of ($i*)
}

rule setuptools_cmd_exec : suspicious {
	meta:
		description = "Python library installer that executes external commands"
	strings:
		$os_system = /os.system\([\"\'\w\ \-\)\/]{0,64}/
		$os_popen = /os.spopen\([\"\'\w\ \-\)\/]{0,64}/
		$subprocess = /subprocess.\w{0,32}\([\"\'\/\w\ \-\)]{0,64}/
	condition:
		pythonSetup and any of them
}

rule setuptools_eval : critical {
	meta:
		description = "Python library installer that evaluates arbitrary code"
	strings:
		$f_sys_val = /eval\([\"\'\w\ \-\)\/]{0,64}/ fullword
		$f_subprocess_val = /exec\([\"\'\/\w\ \-\)]{0,64}/ fullword
	condition:
		pythonSetup and any of ($f*)
}

rule setuptools_os_path_exists : notable {
	meta:
		description = "Python library installer that checks for file existence"
	strings:
		$ref = /[\w\.]{0,8}path.exists\([\"\'\w\ \-\)\/]{0,32}/
	condition:
		pythonSetup and $ref
}