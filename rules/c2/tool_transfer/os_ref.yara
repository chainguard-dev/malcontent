rule os_ref: low {
  meta:
    description = "references a specific operating system"

  strings:
    $ = "macOS"
    $ = "Darwin"
    $ = "Linux"
    $ = "Windows"

  condition:
    any of them
}

rule multiple_os_ref: medium {
  meta:
    description = "references multiple operating systems"

  strings:
    $ = "macOS"
    $ = "Darwin"
    $ = "Linux"
    $ = "Windows"

  condition:
    2 of them
}
