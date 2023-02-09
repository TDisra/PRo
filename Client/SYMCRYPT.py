from cryptography.fernet import Fernet
import os

class SymCrypt():
    def __init__(self, key):
        self.key = key

    def encrypt(self, msg):
        ferObject = Fernet(self.key)
        msgEncrypt = ferObject.encrypt(msg)
        return msgEncrypt

    def decrypt(self, msg):
        ferObject = Fernet(self.key)
        msgDecrypt = ferObject.decrypt(msg)
        return msgDecrypt

    def writeTofileEncrypted(self,file):
        with open(file, "rb") as f:
            data = f.read()
            encryptedData = self.encrypt(data)
        with open(file, "wb") as f:
            f.write(encryptedData)
            
    def writeTofileDecrypted(self,file):
        with open(file, "rb") as f:
            data = f.read()
            decryptedData = self.decrypt(data)
        with open(file, "wb") as f:
            f.write(decryptedData)

    def encryptDir(self,path):
        for i in list(os.walk(path)):
            for n in i[-1]:
                try:
                    print(os.path.join(i[0],n))
                    self.writeTofileEncrypted(os.path.join(i[0],n))
                except:
                    pass

    def decryptDir(self,path):
        for i in list(os.walk(path)):
            for n in i[-1]:
                try:
                    self.writeTofileDecrypted(os.path.join(i[0],n))
                except:
                    pass

    

