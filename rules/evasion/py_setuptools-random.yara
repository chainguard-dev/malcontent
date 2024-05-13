import "math"

private rule pythonSetup {
	strings:
		$i_distutils = "from distutils.core import setup"
		$i_setuptools = "setuptools"
		$setup = "setup("
	condition:
		filesize < 2MB and $setup and any of ($i*)
}

rule setuptools_random : critical {
	meta:
		description = "Python library installer that exhibits random behavior"
	strings:
		$ref = "import random"
	condition:
		pythonSetup and $ref
}
