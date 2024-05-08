
rule macos_tcc_db : suspicious {
  meta:
    description = "access TCC (Transparency, Consent, and Control) database"
  strings:
    $com_apple_TCC = "com.apple.TCC/TCC.db"
    $not_arc = "WelcomeToArc"
    $not_mdm = "MDMOverrides.plist"
  condition:
    $com_apple_TCC and none of ($not*)
}
