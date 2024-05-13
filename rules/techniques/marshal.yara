
import "math"

private rule pySetup {
	strings:
		$i_distutils = "from distutils.core import setup"
		$i_setuptools = "setuptools"
		$setup = "setup("
	condition:
		filesize < 2MB and $setup and any of ($i*)
}

rule py_marshal : notable {
	meta:
		description = "reads python values from binary content"
	strings:
		$ref = "import marshal"
	condition:
		any of them
}

rule setuptools_py_marshal : suspicious {
	meta:
		description = "Python library installer that reads values from binary content"
	condition:
		pySetup and py_marshal
}
