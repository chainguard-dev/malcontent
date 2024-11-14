rule one_three_three_seven: medium {
  meta:
    description = "References 1337 terminology'"

    hash_1985_lib_colors = "270c76aeebb271754a8cc344e8a06ed39749f55bbe10577e227eccfae6ee01b8"
    hash_1985_lib_colors = "4613cd16ce84ce12dcb87bc63da999daededd11a31eda471673dd28a6a844c31"

  strings:
    $ = "1337" fullword
    $ = "L33T" fullword

  condition:
    any of them
}

rule too_l33t_for_me: high {
  meta:
    description = "References 1337 terminology"

  strings:
    $ = "hax0r" fullword
    $ = "hax0rz" fullword
    $ = "HaxErS" fullword
    $ = "FuCkInG" fullword
    $ = "0n Ur" fullword
    $ = "$UICIDEBOY$"

  condition:
    any of them
}
