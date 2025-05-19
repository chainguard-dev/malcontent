rule nodejs_buffer_from: medium {
  meta:
    description = "loads arbitrary bytes from a buffer"
    filetypes   = "js,ts"

  strings:
    $ref = /Buffer\.from\(\[[\d,]{8,63}\)/

  condition:
    any of them
}

rule nodejs_buffer_from_many: high {
  meta:
    description = "loads many arbitrary bytes from a buffer"
    filetypes   = "js,ts"

  strings:
    $ref = /Buffer\.from\(\[[\d,]{63,2048}/

  condition:
    any of them
}
