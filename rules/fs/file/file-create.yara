rule creat: medium {
  meta:
    description = "create a new file or rewrite an existing one"
    syscalls    = "open"
    ref         = "https://man7.org/linux/man-pages/man3/creat.3p.html"

  strings:
    $system = "creat" fullword

  condition:
    all of them in (1000..3000)
}

rule CreateFile: medium {
  meta:
    description = "create a new file"

  strings:
    $create = /CreateFile\w{0,8}/

  condition:
    any of them
}
