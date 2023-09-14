import hashlib
import cffi

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from PyQt5 import QtCore
import tgcrypto

ffi = cffi.FFI()

def read_key(name):
    qstream = readFile(name)
    salt = qstream.readBytes()
    key_encrypted = qstream.readBytes()

    PassKey = createLocalKey(b'', salt)
    keyData = decryptLocal(key_encrypted, PassKey)
    LocalKey = keyData
    return LocalKey


def sha1(data):
    m = hashlib.sha1()
    m.update(data)
    return m.digest()


def sha256(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()


def prepareAES_oldmtp(key, msgKey):
    sha1_a = sha1(msgKey[:16] + key[8:8 + 32])

    sha1_b = sha1(
        key[8 + 32: 8 + 32 + 16]
        + msgKey[:16]
        + key[8 + 48: 8 + 48 + 16]
    )

    sha1_c = sha1(
        key[8 + 64: 8 + 64 + 32] + msgKey[:16])
    sha1_d = sha1(
        msgKey[:16] + key[8 + 96: 8 + 96 + 32])

    aesKey = sha1_a[:8] + sha1_b[8: 8 + 12] + sha1_c[4: 4 + 12]
    aesIv = sha1_a[8: 8 + 12] + sha1_b[:8] + sha1_c[16: 16 + 4] + sha1_d[:8]

    return aesKey, aesIv


def aesIgeDecryptRaw(
    src: bytes,
    key: bytes,
    iv: bytes) -> bytes:
  # Используем Cipher из cryptography для создания AES-IGE шифрования
  cipher = Cipher(algorithms.AES(key), modes.IGE(iv), backend=default_backend())
  # Создаем дешифратор
  decryptor = cipher.decryptor()
  # Возвращаем расшифрованные данные
  return decryptor.update(src) + decryptor.finalize()

def incrementIv(iv: bytes, blockIndex: int) -> bytes:
  if not blockIndex:
    return iv
  digits = 16
  increment = blockIndex
  iv_list = list(iv) # Преобразуем байты в список для изменения элементов
  while digits != 0 and increment != 0:
    digits -= 1
    increment += iv_list[digits]
    iv_list[digits] = increment & 0xFF
    increment >>= 8
  return bytes(iv_list) # Преобразуем список обратно в байты

def my_CRYPTO_ctr128_encrypt(
    src: bytes,
    key: bytes,
    block_index: int,
    iv: bytes) -> bytes:
  # Используем Cipher из cryptography для создания AES-CTR шифрования
  cipher = Cipher(algorithms.AES(key), modes.CTR(incrementIv(iv, block_index)), backend=default_backend())
  # Создаем шифратор
  encryptor = cipher.encryptor()
  # Возвращаем зашифрованные данные
  return encryptor.update(src) + encryptor.finalize()


def aesDecryptLocal(src, key, key128):
    aesKey, aesIV = prepareAES_oldmtp(key, key128)
    dst = tgcrypto.ige256_decrypt(src, aesKey, aesIV)
    return bytearray(dst)


def decryptLocal(encrypted, key):
    encryptedKey = encrypted[:16]
    decrypted = aesDecryptLocal(
        encrypted[16:], key, encryptedKey)
    if sha1(decrypted)[:16] != encryptedKey:
        raise ValueError('bad checksum for decrypted data')

    dataLen = int.from_bytes(decrypted[:4], 'little')
    return decrypted[4:dataLen]


keySize = 256


def createLocalKey(passcode, salt):
    hashKey = hashlib.sha512(salt)
    hashKey.update(passcode)
    hashKey.update(salt)

    iterCount = 100000 if passcode else 1
    dst = hashlib.pbkdf2_hmac("sha512", hashKey.digest(),
                              salt, iterCount, 256)
    return bytearray(dst)


def readFile(name):
    with open(name, 'rb') as f:
        if f.read(4) != b'TDF$':
            #raise ValueError('wrong file type')
            return None

        version = f.read(4)
        data = f.read()

    m = hashlib.md5()
    m.update(data[:-16])
    data_size = len(data)-16
    m.update(data_size.to_bytes(4, 'little'))
    m.update(version)
    m.update(b'TDF$')
    digest = m.digest()

    if digest != data[-16:]:
        raise ValueError('checksum mismatch')

    qbytes = QtCore.QByteArray(data)
    return QtCore.QDataStream(qbytes)


def readEncryptedFile(name, key):
    qstream = readFile(name)
    encrypted = qstream.readBytes()
    return decryptLocal(encrypted, key)


def storage_file_read(path, key):
    with open(path, 'rb') as f:
        if f.read(4) != b'TDEF':
            #raise ValueError('wrong file type')
            return None

        salt = f.read(64)
        encrypted = f.read(16 + 32)

        real_key = sha256(key[:len(key)//2] + salt[:32])
        iv = sha256(key[len(key)//2:] + salt[32:])[:16]
        d = decryptor(real_key, iv)

        data = d.decrypt(encrypted)
        checksum = data[16:]

        if sha256(key + salt + data[:16]) != checksum:
            raise ValueError('wrong key')

        return d.decrypt(f.read())


class decryptor:
    block_index = 0

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def decrypt(self, src):
        #dst = bytearray(len(src))
        #buffer = ffi.from_buffer(dst)
        #iv = ffi.from_buffer(bytearray(self.iv))
        dst = my_CRYPTO_ctr128_encrypt(
            src, self.key, self.block_index, self.iv
        )
        self.block_index += len(src) // 16
        return dst


def main():
    import os

    LocalKey = read_key(r'C:\Users\megapro17\AppData/Roaming/64Gram Desktop/tdata/key_datas')
    topdir = os.path.expanduser(
        r'C:\Users\megapro17\telegram-cache-decryption\o')
    for root, _, files in os.walk(topdir):
        if files:
            newdir = root[len(topdir):].lstrip('/')
            os.makedirs(newdir, exist_ok=True)

        for name in files:
            if name in ['version', 'binlog']:
                continue

            path = os.path.join(root, name)
            print('Decrypting', path)
            data = storage_file_read(path, LocalKey)
            if data != None:
                newf = os.path.join(newdir, name)
                print(newf)
                with open(newf, 'wb') as f:
                    f.write(data)


if __name__ == '__main__':
    main()
