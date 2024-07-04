rule one_three_three_seven : medium {
  meta:
    description = "References 1337 terminology'"
  strings:
    $ = "1337" fullword
	$ = "L33T" fullword
  condition:
    any of them
}

rule too_l33t_for_me : high {
  meta:
    description = "References 1337 terminology'"
  strings:
    $ = "hax0r" fullword
	$ = "hax0rz" fullword
	$ = "HaxErS" fullword
	$ = "FuCkInG" fullword
	$ = "0n Ur" fullword
  condition:
    any of them
}
