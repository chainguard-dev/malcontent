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

rule ansible_shippable_ci: override {
  meta:
    description       = "shippable.sh CI test runners from Ansible collections"
    pip_installer_url = "low"

  strings:
    $shippable    = "SHIPPABLE_BUILD_ID"
    $ansible_test = "ansible-test env --dump"

  condition:
    filesize < 8192 and all of them
}

rule ansible_collection_ci_workflow: override {
  meta:
    description       = "Ansible collection CI workflow installing ansible-core for testing"
    pip_installer_url = "low"

  strings:
    $ansible_core = "Install ansible-core"
    $test_deps    = "ansible-lint docker flake8 molecule"

  condition:
    filesize < 4096 and all of them
}

rule ansible_test_entrypoint: override {
  meta:
    description                                        = "entrypoint.ps1 from ansible-test target setup"
    SIGNATURE_BASE_Suspicious_Powershell_Webdownload_1 = "harmless"

  strings:
    $parser         = "System.Management.Automation.Language.Parser"
    $manifest       = "FromBase64String('{{ MANIFEST }}')"
    $getscriptblock = "GetScriptBlock()"

  condition:
    filesize < 2048 and $parser and any of ($manifest, $getscriptblock)
}
