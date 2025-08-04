rule ansible_override: override {
  meta:
    description                    = "async_wrapper.ps1,become_wrapper.ps1"
    pshome_casing                  = "medium"
    ps_executionpolicy_bypass      = "medium"
    powershell_encoded_command_val = "medium"
    SMTPClient_Send_creds          = "medium"

  strings:
    $ansible = "# (c) 2025 Ansible Project"
    $async   = "#AnsibleRequires -CSharpUtil Ansible._Async"
    $become  = "#AnsibleRequires -CSharpUtil Ansible.Become"

  condition:
    $ansible and ($async or $become)
}
