rule hidden_proc: high linux {
  meta:
    description = "references a hidden path within /proc"

  strings:
    $hidden_proc = /\/proc\/\.\w{1,4}/ fullword

  condition:
    filesize < 10MB and all of them
}

