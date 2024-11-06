rule chdir: harmless {
  meta:
    pledge      = "rpath"
    description = "changes working directory"

  strings:
    $chdir = "chdir" fullword
    $win   = /SetCurrentDirectory\w{0,4}/

  condition:
    any of them
}

rule chdir_shell {
  meta:
    pledge      = "rpath"
    description = "changes working directory"

  strings:
    $val = /cd [\\\"\{\}\$\w\-\_\.\/ \$]{0,16}/ fullword

  condition:
    any of them
}
