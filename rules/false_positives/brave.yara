rule brave_macos: override {
  meta:
    description = "Brave"

  strings:
    $com_browser = "com.brave.Browser"

  condition:
    all of them
}
