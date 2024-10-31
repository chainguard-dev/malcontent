
rule heartbeat : medium {
  meta:
    description = "references a 'heartbeat'"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
  strings:
    $ref = /[\w \:]{0,32}[hH]eart[bB]eat[\w\: ]{0,8}/
  condition:
    any of ($ref*)
}
