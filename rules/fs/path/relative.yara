rule relative_path_val: medium {
  meta:
    description = "references and possibly executes relative path"

    hash_2023_package_bgService = "36831e715a152658bab9efbd4c2c75be50ee501b3dffdb5798d846a2259154a2"
    hash_2023_package_index     = "26f98a78fbb198aec50dc425f53145cc47d031bd4e56fc77fcf22605875f094c"

  strings:
    $ref    = /\.\/[a-z_\-]{2,16}/ fullword
    $up_ref = /\.\.\/[a-z_\-]{2,16}/ fullword

  condition:
    $ref and not $up_ref
}
