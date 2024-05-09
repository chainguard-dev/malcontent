
rule base64_decode : medium python {
  meta:
    description = "decode base64 strings"
    ref = "https://docs.python.org/3/library/base64.html"
    hash_2019_CookieMiner_OAZG = "27ccebdda20264b93a37103f3076f6678c3446a2c2bfd8a73111dbc8c7eeeb71"
    hash_2018_EvilOSX_89e5 = "89e5b8208daf85f549d9b7df8e2a062e47f15a5b08462a4224f73c0a6223972a"
    hash_2020_Enigma = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"
  strings:
    $b64decode = "b64decode"
  condition:
    any of them
}

rule urlsafe_decode64 : medium ruby {
  meta:
    description = "decode base64 strings"
    ref = "https://ruby-doc.org/3.3.0/stdlibs/base64/Base64.html"
    hash_2019_active_controller_middleware = "9a85e7aee672b1258b3d4606f700497d351dd1e1117ceb0e818bfea7922b9a96"
    hash_2023_1_1_6_payload = "cbe882505708c72bc468264af4ef5ae5de1b75de1f83bba4073f91568d9d20a1"
    hash_2023_0_0_7_payload = "bb6ca6bfd157c39f4ec27589499d3baaa9d1b570e622722cb9bddfff25127ac9"
  strings:
    $urlsafe_decode64_ruby = "urlsafe_decode64"
  condition:
    any of them
}

rule powershell_decode : medium {
  meta:
    description = "decode base64 strings"
    ref = "https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string?view=net-8.0"
  strings:
    $ref = "[System.Convert]::FromBase64String" ascii
  condition:
    any of them
}
