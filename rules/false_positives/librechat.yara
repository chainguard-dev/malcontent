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
