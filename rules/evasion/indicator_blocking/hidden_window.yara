rule subprocess_CREATE_NO_WINDOW: medium {
  meta:
    description = "runs commands, hides windows"
    filetypes   = "py"

  strings:
    $sub       = "subprocess"
    $no_window = "CREATE_NO_WINDOW"

  condition:
    filesize < 32KB and all of them
}

private rule hidden_window_pythonSetup {
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
    filesize < 128KB and $setup and any of ($i*) in (0..1024) and none of ($not*)
}

rule subprocess_CREATE_NO_WINDOW_setuptools: high {
  meta:
    description = "runs commands, hides windows"
    filetypes   = "py"

  strings:
    $sub       = "subprocess"
    $no_window = "CREATE_NO_WINDOW"

  condition:
    filesize < 32KB and hidden_window_pythonSetup and all of them
}

rule subprocess_CREATE_NO_WINDOW_high: high {
  meta:
    description = "runs commands, hides windows"
    filetypes   = "py"

  strings:
    $s_sub       = "subprocess"
    $s_no_window = "CREATE_NO_WINDOW"

    $o_discord = "discordapp.com"

  condition:
    filesize < 32KB and all of ($s*) and any of ($o*)
}
