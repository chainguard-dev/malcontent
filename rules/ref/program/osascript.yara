
rule osascript_caller : medium {
  meta:
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
  strings:
    $o_osascript = "osascript" fullword
    $o_osascript_e = "osascript -e"
    $o_display_dialog = "display dialog"
    $o_with_hidden_answer = "with hidden answer"
    $o_default = "default button \""
  condition:
    any of ($o*)
}
