rule localstorage: medium {
  meta:
    description = "accesses browser local storage"

  strings:
    $ref = "localStorage.get"

  condition:
    any of them
}
