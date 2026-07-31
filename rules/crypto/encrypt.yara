rule encrypt: medium {
  meta:
    description = "encrypts data"

  strings:
    $encrypt = /[\w ]{0,16}Encrypt[\w ]{0,16}/
    $ref     = /Encrypt[\w]{0,16}/

    $not_encrypted = "Encrypted"

  condition:
    // "Encrypted" is itself an instance of the text $encrypt generalises, so that
    // one word used to excuse every other Encrypt* mention in the file. $encrypt
    // cannot do the counting: its leading [\w ]{0,16} run starts a separate
    // overlapping match at every offset inside the preceding word, so a single
    // "tempkeyEncrypted" already reports more than a dozen matches. $ref carries
    // the same reference text anchored at the E, which yields one match per
    // occurrence, so each "Encrypted" cancels exactly one $ref match and the rule
    // needs an Encrypt* spelling the accepted word does not account for. $encrypt
    // is kept because it reports the surrounding context.
    $encrypt and #ref > #not_encrypted
}

rule file_crypter: medium {
  meta:
    description = "Encrypts files"

  strings:
    $ref  = "Files encrypted"
    $ref2 = "Encrypting file"
    $ref3 = "encrypts files"
    $ref4 = "files_encrypted"
    $ref5 = "EncryptFile"
    $ref6 = "cryptor" fullword

  condition:
    any of them
}
