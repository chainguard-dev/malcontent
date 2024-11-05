rule py_builtins {
  meta:
    description = "references Python builtins"

  strings:
    $ref = "__builtins__" fullword

  condition:
    $ref
}

rule py_indirect_builtins: suspicious {
  meta:
    description                   = "Indirectly refers to Python builtins"
    hash_2023_yfinancce_0_1_setup = "3bde1e9207dd331806bf58926d842e2d0f6a82424abd38a8b708e9f4e3e12049"
    hash_2023_yvper_0_1_setup     = "b765244c1f8a11ee73d1e74927b8ad61718a65949e0b8d8cbc04e5d84dccaf96"
    hash_2023_aiohttpp_0_1_setup  = "cfa4137756f7e8243e7c7edc7cb0b431a2f4c9fa401f2570f1b960dbc86ca7c6"

  strings:
    $val = /getattr\(__builtins__,[ \w\.\)\)]{0,64}/

  condition:
    any of them
}

private rule pythonSetup {
  strings:
    $if_distutils  = /from distutils.core import .{0,32}setup/
    $if_setuptools = /from setuptools import .{0,32}setup/
    $i_setuptools  = "import setuptools"
    $setup         = "setup("

    $not_setup_example = ">>> setup("
    $not_setup_todict  = "setup(**config.todict()"
    $not_import_quoted = "\"from setuptools import setup"
    $not_setup_quoted  = "\"setup(name="
    $not_distutils     = "from distutils.errors import"

  condition:
    filesize < 128KB and $setup and any of ($i*) and none of ($not*)
}

rule setuptools_builtins: notable {
  meta:
    description = "Python library installer that references builtins"

  condition:
    pythonSetup and py_builtins
}
