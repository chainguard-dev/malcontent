rule desktop_app_exec_entry: medium {
  meta:
    description = "creates an XDG Desktop Entry to execute an application"

  strings:
    $ = "[Desktop Entry]"
    $ = "Type=Application"
    $ = "Exec="

  condition:
    filesize < 20MB and all of them
}

rule elf_desktop_app_exec_entry: high {
  meta:
    description = "persists via an XDG Desktop Entry"
    filetypes   = "elf"

  strings:
    $ = "[Desktop Entry]"
    $ = "Type=Application"
    $ = "Exec="

  condition:
    filesize < 20MB and uint32(0) == 1179403647 and all of them
}
