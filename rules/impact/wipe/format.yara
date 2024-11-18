rule format_c: critical windows {
  meta:
    description = "forcibly formats the C:\\ drive"

  strings:
    $format = /(format|FORMAT).{1,4}[Cc]:\\.{1,4}\/[yY]/

  condition:
    any of them
}
