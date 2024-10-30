rule backtrace: harmless {
  meta:
    description = "call stack backtrace and display functions"
    pledge      = "id"

  strings:
    $backtrace               = "_backtrace" fullword
    $backtrace_symbols       = "backtrace_symbols" fullword
    $backtrace_symbols_fd    = "backtrace_symbols_fd" fullword
    $backtrace_image_offsets = "backtrace_image_offsets" fullword
    $backtrace_from_fp       = "backtrace_from_fp" fullword

  condition:
    any of them
}
