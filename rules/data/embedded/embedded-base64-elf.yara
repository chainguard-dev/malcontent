rule base64_elf: high {
  meta:
    description = "Contains base64 encoded ELF binary"

  strings:
    $header = "f0VMRgEBAQ"

  condition:
    $header
}
