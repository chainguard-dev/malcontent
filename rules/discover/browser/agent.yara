rule user_agent_data: low {
  meta:
    description = "gets browser user-agent"

  strings:
    $ref = "navigator.userAgentData.get"

  condition:
    any of them
}
