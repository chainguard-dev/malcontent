rule trojan_project: low {
  meta:
    description = "Trojan GFW bypass"

  strings:
    $ref1 = "part of the trojan project."
    $ref2 = "Copyright (C) 2017-2020  The Trojan Authors"

  condition:
    any of them
}
