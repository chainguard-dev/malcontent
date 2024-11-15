rule password_finder_generic: high {
  meta:
    description = "password finder or dumper"

  strings:
    $ref  = "findPassword"
    $ref2 = "find_password"

  condition:
    filesize < 25MB and any of them
}

rule gnome_keyring_sync: override {
  meta:
    description             = "looks up passwords via gnome_keyring"
    password_finder_generic = "medium"

  strings:
    $ref = "gnome_keyring_find_password_sync"

  condition:
    filesize > 5MB and any of them
}

rule password_dumper_generic: high {
  meta:
    description = "password dumper"

  strings:
    $ref3 = "dumpPassword"
    $ref4 = "dump_password"

  condition:
    any of them
}
