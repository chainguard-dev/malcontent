rule base64_encode: medium python {
  meta:
    description = "encode base64 strings"
    ref         = "https://docs.python.org/3/library/base64.html"

  strings:
    $b64encode = "b64encode"

  condition:
    any of them
}

rule py_base64_encode: medium php {
  meta:
    description = "encode base64 strings"

  strings:
    $b64encode = "base64_encode"

  condition:
    any of them
}

rule ruby_base64_encode: medium ruby {
  meta:
    description = "encode base64 strings"

  strings:
    $b64encode = /[\._]encode64/

  condition:
    any of them
}

rule urlsafe_encode64: medium ruby {
  meta:
    description = "encode base64 strings"
    ref         = "https://ruby-doc.org/3.3.0/stdlibs/base64/Base64.html"

  strings:
    $urlsafe_encode64_ruby = "urlsafe_encode64"

  condition:
    any of them
}

rule powershell_encode: medium {
  meta:
    description = "encode base64 strings"
    ref         = "https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string?view=net-8.0"

  strings:
    $ref = /System\.Convert[\]: ]+ToBase64String/ ascii

  condition:
    any of them
}

rule java_base64_encode: medium {
  meta:
    description = "encode base64 strings"

  strings:
    $ref = "Base64$Encoder"

  condition:
    any of them
}
