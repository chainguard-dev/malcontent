rule shc: high {
  meta:
    description = "Binary generated with SHC (Shell Script Compiler)"
    ref         = "https://github.com/neurobin/shc"

  strings:
    $ref = "argv[0] nor $_"

  condition:
    $ref
}
