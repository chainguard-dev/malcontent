rule malicious: medium {
  meta:
    description = "References 'malicious'"

  strings:
    $ref  = /[a-zA-Z\-_ ]{0,16}malicious[a-zA-Z\-_ ]{0,16}/ fullword
    $word = "malicious"

    $not_sshd = "attempt by a malicious server"

  condition:
    // $ref carries up to 16 characters of context, so a single "malicious" yields
    // several $ref matches (one per word start) and cannot be counted directly. Count
    // the bare word instead: OpenSSH's "attempt by a malicious server" contributes
    // exactly one, so fire only on an occurrence it does not account for rather than
    // letting that one message suppress every other mention in the file.
    $ref and #word > #not_sshd
}

rule malici0us: high {
  meta:
    description = "References 'malici0us'"

  strings:
    $ref = /[a-zA-Z\-_ ]{0,16}malici0us[a-zA-Z\-_ ]{0,16}/ fullword

  condition:
    any of them
}
