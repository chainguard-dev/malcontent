rule password {
  meta:
    description = "references a 'password'"

  strings:
    $ref  = /[a-zA-Z\-_ ]{0,16}password[a-zA-Z\-_ ]{0,16}/ fullword
    $ref2 = /[a-zA-Z\-_ ]{0,16}Password[a-zA-Z\-_ ]{0,16}/ fullword

  condition:
    any of them
}
