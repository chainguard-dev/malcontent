rule base64_decode: medium python {
  meta:
    description = "decode base64 strings"
    ref         = "https://docs.python.org/3/library/base64.html"


    hash_2020_Enigma       = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"

  strings:
    $b64decode = "b64decode"

  condition:
    any of them
}

rule py_base64_decode: medium php {
  meta:
    description       = "decode base64 strings"




  strings:
    $b64decode = "base64_decode"

  condition:
    any of them
}

rule urlsafe_decode64: medium ruby {
  meta:
    description = "decode base64 strings"
    ref         = "https://ruby-doc.org/3.3.0/stdlibs/base64/Base64.html"




  strings:
    $urlsafe_decode64_ruby = "urlsafe_decode64"

  condition:
    any of them
}

rule powershell_decode: medium {
  meta:
    description = "decode base64 strings"
    ref         = "https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string?view=net-8.0"

  strings:
    $ref = /System\.Convert[\]: ]+FromBase64String/ ascii

  condition:
    any of them
}
