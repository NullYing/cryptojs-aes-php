# -*- coding: utf-8 -*-
# 傲娇的仓库作者不需要py版本，fork一下备份

import binascii
import base64
import hashlib
import json
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):
    bs = 16

    @staticmethod
    def md5(s, raw_output=False):
        """Calculates the md5 hash of a given string"""
        if isinstance(s, str):
            s = s.encode()
        res = hashlib.md5(s)
        if raw_output:
            return res.digest()
        return res.hexdigest()

    def encrypt(self, data, key, salt=None):
        """
        :param data: str
        :param key: str
        :param salt: str
        :return:
        """
        if not salt:
            salt = Random.new().read(8)
        else:
            salt = binascii.unhexlify(salt)
        salted = b''
        dx = b''
        while len(salted) < 48:
            dx = self.md5(dx + key.encode('utf-8') + salt, True)
            salted += dx
        key = salted[:32]
        iv = salted[-16:]
        raw = self._pad(json.dumps(data).replace(' ', ''))

        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(raw.encode('utf-8'))
        return base64.b64encode(enc), binascii.hexlify(iv), binascii.hexlify(salt)

    def decrypt(self, enc, iv, key, salt):
        """
        :param enc: str
        :param iv: str
        :param key: str
        :param salt: str
        :return:
        """
        concated_passphrase = key.encode() + binascii.unhexlify(salt)
        md5_salt = self.md5(concated_passphrase, True)
        md5_list = [md5_salt]
        result = md5_list[0]
        for i in [1, 2]:
            md5_list.append(self.md5(md5_list[i - 1] + concated_passphrase, True))
            result += md5_list[i]
        key = result[:32]

        enc = base64.b64decode(enc)
        iv = binascii.unhexlify(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc)).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]