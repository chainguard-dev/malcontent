rule localstorage: medium {
  meta:
    description = "accesses browser local storage"
    filetypes   = "application/javascript"

  strings:
    $ref = "localStorage.get"

  condition:
    any of them
}
