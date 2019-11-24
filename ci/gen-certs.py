import subprocess

retval = subprocess.run(["which", "openssl"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
retval.check_returncode()
openssl_path = retval.stdout.decode().strip()

print(openssl_path)
