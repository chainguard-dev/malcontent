rule dropper: medium {
  meta:
    description = "References 'dropper'"

    hash_2017_BadBunny = "3ca31b2adb859da61747f8c60c10afddde43b739482aeb104d992ef5764cac7c"

  strings:
    $ref  = "dropper" fullword
    $ref2 = "Dropper" fullword

  condition:
    any of them
}

rule dropper_for: high {
  meta:
    description = "References 'dropper for'"

    hash_2017_BadBunny = "3ca31b2adb859da61747f8c60c10afddde43b739482aeb104d992ef5764cac7c"

  strings:
    $ref = /[dD]ropper for [\w ]{0,32}/

  condition:
    any of them
}
