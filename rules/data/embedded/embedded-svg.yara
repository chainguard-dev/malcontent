rule svg: harmless {
  meta:
    description = "Contains SVG (Scalable Vector Graphics) content"

  strings:
    $lower1 = "<svg>"
    $lower2 = "</svg>"
    $upper1 = "<SVG>"
    $upper2 = "</SVG>"

  condition:
    all of ($lower*) or all of ($upper*)
}

rule foreign_object: medium {
  meta:
    description = "Contains SVG (Scalable Vector Graphics) content using foreignObjects"

  strings:
    $foreign_obj_open  = "<foreignObject>" nocase
    $foreign_obj_close = "</foreignObject>" nocase

  condition:
    svg and all of them
}

rule foreign_object_script: high {
  meta:
    description = "Contains SVG (Scalable Vector Graphics) content that uses foreignObjects along with base64, images, input, obfuscated variables, or scripts"

  strings:
    $base64_str     = /[\"\'][\w\/\+]{24,2048}==[\"\']/
    $i_button       = "<button" nocase
    $i_img          = "data:image/" wide ascii
    $i_input_pass   = "<input" nocase
    $i_onclick      = "onclick=" nocase
    $i_type_pass    = "type=\"password\"" nocase
    $obfuscated_var = /_0x[0-9a-f]{4,}/
    $s_cdata        = "<![CDATA["
    $s_script_tag   = "<script" nocase
    $xhtml          = "xhtml" nocase
    $xml            = "xmlns" nocase

  condition:
    svg and foreign_object and (any of ($i*) or ($base64_str or $obfuscated_var) or ($xhtml or $xml or any of ($s*)))
}
