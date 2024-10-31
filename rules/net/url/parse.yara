rule url_handle {
  meta:
    description = "Handles URL strings"

  strings:
    $ref  = "NSURL"
    $ref2 = "URLContext"
    $ref3 = "RequestURI"
    $ref4 = "urllib"
    $re5  = "new URL"

  condition:
    any of them
}
