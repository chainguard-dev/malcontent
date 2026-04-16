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

rule ansible_report_coverage: override {
  meta:
    description       = "report-coverage.sh from Ansible collections CI scripts"
    pip_installer_url = "low"

  strings:
    $coverage  = "ansible-test coverage xml"
    $pipelines = "Generate code coverage reports for uploading to Azure Pipelines"

  condition:
    filesize < 2048 and all of them
}
