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


    

