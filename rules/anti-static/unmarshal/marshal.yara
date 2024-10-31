import "math"

private rule pySetup {
  strings:
    $i_distutils    = "from distutils.core import setup"
    $i_setuptools   = "setuptools"
    $setup          = "setup("
    $not_setuptools = "setuptools.command"

  condition:
    filesize < 2097152 and $setup and any of ($i*) and none of ($not*)
}

rule py_marshal: medium {
  meta:
    description                       = "reads python values from binary content"
    hash_2021_DiscordSafety_init      = "05c23917c682326179708a1d185ea88632d61522513f08d443bfd5c065612903"
    hash_2021_DiscordSafety_0_1_setup = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"
    hash_2024_ForgePy_init            = "298220bc98a9174700d2e081843fbf3e34be1ad838cea93e0a2a94b9109a04b7"

  strings:
    $ref = "import marshal"

  condition:
    filesize < 128KB and any of them
}

rule setuptools_py_marshal: suspicious {
  meta:
    description = "Python library installer that reads values from binary content"

  condition:
    pySetup and py_marshal
}
