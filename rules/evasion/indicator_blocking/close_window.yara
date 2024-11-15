rule tell_terminal_to_close: high {
  meta:
    description = "closes Terminal window"

  strings:
    $close = "tell application \"Terminal\" to close first window"

  condition:
    filesize < 10MB and all of them
}
