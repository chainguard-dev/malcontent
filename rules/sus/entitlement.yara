include "rules/global.yara"

rule com_apple_get_task_allow: medium {
  meta:
    description = "debug binary"
    filetypes   = "macho"

  strings:
    $get_task_allow = "<key>com.apple.security.get-task-allow</key>"
    $true           = "<true/>"

  condition:
    specific_macho and all of them
}
