rule pre_term_name {
  strings:
    $ref = "<pre_term_name("

  condition:
    any of them
}
