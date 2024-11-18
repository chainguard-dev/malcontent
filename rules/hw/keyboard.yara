rule keyboard_library: medium {
  meta:
    description = "accesses keyboard events"

  strings:
    $import_pynput   = "import pynput"
    $import_keyboard = "import keyboard"
    $keyboard        = "keyboard" fullword

  condition:
    filesize < 256KB and $keyboard and any of ($import*)
}
