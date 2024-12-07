rule ip_connect: medium {
  meta:
    description = "opens a network connection"

  strings:
    $open_connection = "openConnection" fullword

  condition:
    any of them
}
