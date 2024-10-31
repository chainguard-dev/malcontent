rule TERM {
  meta:
    description = "Look up or override terminal settings"
    ref         = "https://www.gnu.org/software/gettext/manual/html_node/The-TERM-variable.html"

  strings:
    $ref = "TERM" fullword
  //	$getenv = "getenv"

  condition:
    all of them
}
