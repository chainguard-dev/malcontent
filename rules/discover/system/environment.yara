rule os_environ: medium {
  meta:
    description = "Dump values from the environment"
    filetypes   = "py"

  strings:
    $ref = "os.environ.items()" fullword

  condition:
    any of them
}
