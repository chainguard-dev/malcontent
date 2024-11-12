rule pycloak: critical {
  meta:
    description = "packed with pycloak"
    ref         = "https://github.com/addi00000/pycloak"

  strings:
    $ = "__builtins__.__dict__[__builtins__.__dict__"
    $ = "__builtins__.__dict__[bytes([(lambda"
    $ = ").decode(bytes([(lambda"

  condition:
    filesize < 250KB and 2 of them
}
