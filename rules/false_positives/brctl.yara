rule brctl: override macos {
  meta:
    description          = "brctl"
    chmod_dangerous_exec = "medium"

  strings:
    $brctl = "@(#)PROGRAM:brctl"

  condition:
    all of them
}
