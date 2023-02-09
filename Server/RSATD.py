from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

class RSACrypt(object):
    
    def __init__(self,key=False):
        if key:
            if type(key) == dict:
                if 'private' in list(key.keys()):
                    key = key['private']
                else: key = key['public']
            self.key = key
            self.cipher = PKCS1_OAEP.new(key)
            
    def genKeys(self,nbit):
        fullkey = RSA.generate(nbit)
        public = fullkey.public_key()
        return {'public':public,'private':fullkey}
    
    
    def encrypt(self,data):
        return self.cipher.encrypt(data)
    
    
    def decrypt(self,encData):
        return self.cipher.decrypt(encData)
    
    def genPem(self,key=False):
        if key:
            return key.export_key()
        return self.key.export_key()
        
    def importKey(self,pemKey):
        key = RSA.import_key(pemKey)
        if 'd' in str(key):
            return {'private':key,'public':key.public_key()}
        return {'public':key}
    
       