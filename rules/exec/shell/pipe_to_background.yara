rule pipe_to_bg: medium {
  meta:
    description = "pipes to backgrounded shell"

  strings:
    $ref = "| sh &"

  condition:
    $ref
}
