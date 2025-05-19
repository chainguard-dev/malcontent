rule kramer: critical {
  meta:
    description = "packed with Kramer"
    ref         = "https://github.com/billythegoat356/Kramer"
    filetypes   = "py"

  strings:
    $ = ".__init__.<locals>.<lambda>.<locals>.<genexpr>"
    $ = "unhexlify"
    $ = "_sparkleN"
    $ = "decode"
    $ = "returnc"
    $ = "split"
    $ = "obf.py"

  condition:
    filesize < 10MB and all of them
}

rule py_kramer_packer2: critical python {
  meta:
    description = "packed with Kramer"
    ref         = "https://github.com/billythegoat356/Kramer"
    filetypes   = "py"

  strings:
    $ = "class Kramer():"
    $ = "def __decode__(self:object,_execute:str)->exec:return"
    $ = "def __init__(self:object,_delete:float=False"
    $ = "self._exit,_delete,self._eval,"
    $ = "_delete=False,_bit=False,_sparkle='''"

  condition:
    filesize < 10MB and 3 of them
}

rule py_kramer_packer3: critical python {
  meta:
    description = "packed with Kramer"
    ref         = "https://github.com/billythegoat356/Kramer"
    filetypes   = "py"

  strings:
    $ = "Kramer.__decode__"
    $ = "Kramer.__init__.<locals>.<lambda>.<locals>.<genexpr>"
    $ = "Kramer.__init__.<locals>.<lambda>"

  condition:
    filesize < 10MB and any of them
}
