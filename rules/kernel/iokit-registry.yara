rule IORegistry {
  meta:
    description = "access IOKit device driver registry"

  strings:
    $ref = "IORegistry"

  condition:
    any of them
}
