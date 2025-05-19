rule nspasteboard: medium macos {
  meta:
    ref         = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"
    description = "access clipboard contents"

  strings:
    $pb1        = "NSPasteboard" fullword
    $pb2        = "pbpaste" fullword
    $lib        = "golang.design/x/clipboard"
    $lib2       = "atotto/clipboard"
    $lib_user32 = "user32.GetClipboardData"

  condition:
    all of ($pb*) or any of ($lib*)
}

rule py_pasteboard: high {
  meta:
    description = "access clipboard contents"
    filetypes   = "py"

  strings:
    $clip   = "pyperclip.copy("
    $pandas = "pandas.read_clipboard("

  condition:
    any of them
}
