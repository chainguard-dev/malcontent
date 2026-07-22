rule openstack_ironic_redfish_firmware: override {
  meta:
    description          = "redfish_firmware.py from dellemc.openmanage Ansible collection"
    http_ip_url_with_exe = "low"

  strings:
    $dell    = "Dell OpenManage Ansible Modules"
    $redfish = "dellemc.openmanage.redfish_firmware"

  condition:
    filesize < 20480 and all of them
}

rule openstack_ironic_test_firmware_utils: override {
  meta:
    description          = "test_firmware_utils.py from OpenStack Ironic test suite"
    http_ip_url_with_exe = "low"

  strings:
    $ironic_test = "from ironic.tests import base"
    $firmware    = "from ironic.drivers.modules.redfish import firmware_utils"

  condition:
    filesize < 40960 and all of them
}
