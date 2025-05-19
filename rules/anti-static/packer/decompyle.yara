rule py_kramer_packer: critical python {
  meta:
    description = "packed with Kramer"
    ref         = "https://github.com/billythegoat356/Kramer"
    filetypes   = "py"

  strings:
    $ = "Source Generated with Decompyle++"
    $ = /_{1,16} = eval\(getattr\(__import__\(bytes\(\[/

  condition:
    filesize < 8MB and any of them
}
