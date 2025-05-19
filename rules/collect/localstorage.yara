rule localstorage: medium {
  meta:
    description = "accesses browser local storage"
    filetypes   = "js,ts"

  strings:
    $ref = "localStorage.get"

  condition:
    any of them
}
