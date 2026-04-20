rule librechat_anthropic_thinking: override {
  meta:
    description                                                       = "@librechat/agents Anthropic Claude thinking tests and scripts"
    SIGNATURE_BASE_SUSP_Claude_Redacted_Thinking_Magic_String_Jan26_1 = "harmless"
    SIGNATURE_BASE_SUSP_Claude_Redacted_Thinking_Magic_String_Jan26_2 = "harmless"

  strings:
    $anchor1  = "createContentAggregator"
    $anchor2  = "_convertMessagesToAnthropicPayload"
    $thinking = "ANTHROPIC_MAGIC_STRING_TRIGGER_REDACTED_THINKING_"

  condition:
    filesize < 200KB and $thinking and 1 of ($anchor*)
}

rule librechat_pdfjs_worker: override {
  meta:
    description = "Mozilla PDF.js worker bundles (build/ and legacy/build/) shipped under pdfjs-dist"
    xor_certs   = "low"
    xor_terms   = "low"
    xor_url     = "low"

  strings:
    $anchor1 = "pdfjsVersion = "
    $anchor2 = "pdfjsBuild = "
    $anchor3 = "pdfjs_internal_editor_"

  condition:
    filesize < 3MB and all of them
}
