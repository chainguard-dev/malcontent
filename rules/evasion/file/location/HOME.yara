rule custom_home: medium linux {
  meta:
    description = "overrides the HOME directory environment variable"

  strings:
    $ref      = /HOME=\/[a-z][\.\w\/]{0,24}/ fullword
    $not_root = "HOME=/root" fullword

  condition:
    // "HOME=/root" is itself a $ref match, so compare counts: it cancels its
    // own occurrence and any other HOME override still fires. $not_root gained
    // fullword so its boundaries line up with $ref's and each cancels one match.
    #ref > #not_root
}
