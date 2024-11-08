rule dropper: medium {
  meta:
    description              = "References 'dropper'"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2017_BadBunny       = "3ca31b2adb859da61747f8c60c10afddde43b739482aeb104d992ef5764cac7c"

  strings:
    $ref  = "dropper" fullword
    $ref2 = "Dropper" fullword

  condition:
    any of them
}

rule dropper_for: high {
  meta:
    description              = "References 'dropper for'"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2017_BadBunny       = "3ca31b2adb859da61747f8c60c10afddde43b739482aeb104d992ef5764cac7c"

  strings:
    $ref  = /[dD]ropper for [\w ]{0,32}/
	
  condition:
    any of them
}
