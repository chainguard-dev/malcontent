rule browser_platform: low {
  meta:
    description = "gets browser user-agent"

  strings:
    $ref  = "navigator.userAgentData.get"

  condition:
    any of them
}
