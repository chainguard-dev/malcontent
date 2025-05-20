include "rules/global.yara"

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

rule subprocess_CREATE_NO_WINDOW_setuptools: high {
  meta:
    description = "runs commands, hides windows"
    filetypes   = "py"

  strings:
    $sub       = "subprocess"
    $no_window = "CREATE_NO_WINDOW"

  condition:
    filesize < 32KB and python_setup and all of them
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
