rule py_builtins {
	meta:
		description = "references Python builtins"
	strings:
		$ref = "__builtins__" fullword
	condition:
		$ref
}

rule py_indirect_builtins : suspicious {
  meta:
	description = "Indirectly refers to Python builtins"
  strings:
	$val = /getattr\(__builtins__,[ \w\.\)\)]{0,64}/
condition:
	any of them
}

private rule pythonSetup {
	strings:
		$i_distutils = "from distutils.core import setup"
		$i_setuptools = "setuptools"
		$setup = "setup(" fullword
	condition:
		filesize < 32768 and $setup and any of ($i*)
}

rule setuptools_builtins : notable {
	meta:
		description = "Python library installer that references builtins"
	condition:
		pythonSetup and py_builtins
}
