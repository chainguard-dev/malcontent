rule open_base64: high {
  meta:
    description = "opens locations based on base64 encoded content"
    filetypes   = "py"

  strings:
    $import   = "import" fullword
    $open     = /.{0,8}open\(.{0,8}\.b64decode.{0,64}/
    $requests = /requests\.[a-z]{0,4}\(.{0,8}\.b64decode.{0,64}/

  condition:
    filesize < 512KB and $import and ($open or $requests)
}
