rule msxml2_http: critical {
  meta:
    description = "padded form of MSXML2.HTTP"

  strings:
    $a = /M.{0,48}S.{0,48}X.{0,48}M.{0,48}L.{0,48}2.{0,48}\.X.{0,48}M.{0,48}L.{0,48}H.{0,48}T.{0,48}T.{0,48}P.{0,48}/

    // https://github.com/mailru/FileAPI/blob/5b50e8ed012e089eb578e586d860a6fd035e16d8/lib/FileAPI.core.js#L298
    $not_fileapi  = "MSXML2.XMLHttp.3.0\")}catch(c){b=new ActiveXObject(\"Microsoft.XMLHTTP\")}return b},isArray:l,support:{dnd:s&&\"ondrop\"i"
    $not_i18next1 = "i18nextHttpBackend"
    $not_i18next2 = "u[\"User-Agent\"]=\"i18next-http-backend (node/\".concat(S.process.version,\"; \")"
    $not_yui1     = "Copyright (c) 2008, Yahoo! Inc. All rights reserved."
    $not_yui2     = "http://developer.yahoo.net/yui/license.txt"
    $not_yui3     = "version: 2.6.0"
    $not_yui4     = "YAHOO.util.Connect={_msxml_progid:[\"Microsoft.XMLHTTP\",\"MSXML2.XMLHTTP.3.0\",\"MSXML2.XMLHTTP\"]"
    $not_yui5     = "if(typeof YAHOO==\"undefined\"||!YAHOO){var YAHOO={};}YAHOO.namespace=function()"

  condition:
    filesize < 128KB and $a and !a > 32 and none of ($not*)
}

rule obfuscation_base64_str_replace: medium {
  meta:
    description = "creatively hidden forms of the term 'base64'"

  strings:
    $a = /\wba\ws\we64/
    $b = /\wb\wa\wse\w6\w4/
    $c = /\wba\ws\we\w6\w4/
    $d = /\wb\was\we\w6\w4/
    $e = /\wb\wa\ws\we6\w4/
    $f = /\wb\wa\ws\we\w64/
    $g = "'bas'.'e'.'6'.'4"
    $h = "'ba'.'se'.'6'.'4"
    $i = "'b'.'ase'.'6'.'4"
    $j = "'bas'.'e'.'6'.'4"

  condition:
    any of them
}

rule gzinflate_str_replace: critical {
  meta:
    description = "creatively hidden forms of the term 'gzinflate'"

  strings:
    $a = /g.z.inf.l.a/
    $b = /g.z.i.n.f.l/
    $c = /g.z.in.f.l/

  condition:
    any of them
}

rule funky_function: critical {
  meta:
    description = "creatively hidden forms of the term 'function'"
    filetypes   = "php"

  strings:
    $a = "'fu'.'nct'.'ion'"
    $b = "'f'.'unc'.'tion'"
    $c = "'fun'.'nc'.'tion'"
    $d = "'fun'.'ncti'.'on'"

  condition:
    any of them
}
