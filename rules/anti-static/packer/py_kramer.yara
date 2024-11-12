rule pycloak: critical {
  meta:
    description = "packed with kramer"
    ref         = "https://github.com/billythegoat356/Kramer"

  strings:
    $ = ".__init__.<locals>.<lambda>.<locals>.<genexpr>"
    $ = "unhexlify"
    $ = "_sparkleN"
    $ = "decode"
    $ = "returnc"
    $ = "split"
    $ = "obf.py"

  condition:
    filesize < 8MB and all of them
}
