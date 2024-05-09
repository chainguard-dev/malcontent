
rule __progname : medium {
  meta:
    description = "get or set the current process name"
    ref = "https://stackoverflow.com/questions/273691/using-progname-instead-of-argv0"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_039e = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
    hash_2024_Downloads_0ca7 = "0ca7e0eddd11dfaefe0a0721673427dd441e29cf98064dd0f7b295eae416fe1b"
  strings:
    $ref = "__progname"
  condition:
    any of them
}

rule bash_sets_name_val : medium {
  meta:
    description = "sets process name"
    ref = "https://www.jamf.com/blog/cryptojacking-macos-malware-discovered-by-jamf-threat-labs/"
  strings:
    $ref = /exec -a[ \"\$\{\}\@\w\/\.]{0,64}/
  condition:
    any of them
}
