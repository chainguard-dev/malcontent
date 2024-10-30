rule tail_byte_offsets: medium {
  meta:
    description = "uses the tail command with exotic offset values"

  strings:
    $val = /tail -c \+\d{3,8}/

  condition:
    any of them
}

rule head_byte_offsets: medium {
  meta:
    description = "uses the head command with exotic offset values"

  strings:
    $val = /head -c \+\d{3,8}/

  condition:
    any of them
}
