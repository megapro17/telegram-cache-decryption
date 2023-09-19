import argparse
import concurrent.futures
import hashlib
import io 
import magic
import os
import tgcrypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pathlib import Path


def read_key(name):
    data = read_keyfile(name)
    salt = data.read(32)
    data.read(4)
    key_encrypted = data.read(288)
    # Я не знаю чё за оффсеты так считывал QByteArray

    pass_key = create_local_key(b'', salt)
    key_data = decrypt_local(key_encrypted, pass_key)
    local_key = key_data
    return local_key

def read_keyfile(name):
    with open(name, 'rb') as f:
        if f.read(4) != b'TDF$':
            print('wrong file type')
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
        print('checksum mismatch')
        return None

    data = io.BytesIO(data)
    data.seek(4)
    return data

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

def increment_iv(iv: bytes, blockIndex: int) -> bytes:
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

def ctr128_encrypt(
    src: bytes,
    key: bytes,
    block_index: int,
    iv: bytes) -> bytes:
  # Используем Cipher из cryptography для создания AES-CTR шифрования
  cipher = Cipher(algorithms.AES(key), modes.CTR(increment_iv(iv, block_index)), backend=default_backend())
  # Создаем шифратор
  encryptor = cipher.encryptor()
  # Возвращаем зашифрованные данные
  return encryptor.update(src) + encryptor.finalize()


def aes_decrypt_local(src, key, key128):
    aesKey, aesIV = prepareAES_oldmtp(key, key128)
    dst = tgcrypto.ige256_decrypt(src, aesKey, aesIV)
    return bytearray(dst)


def decrypt_local(encrypted, key):
    encryptedKey = encrypted[:16]
    decrypted = aes_decrypt_local(
        encrypted[16:], key, encryptedKey)
    if sha1(decrypted)[:16] != encryptedKey:
        raise ValueError('bad checksum for decrypted data')

    dataLen = int.from_bytes(decrypted[:4], 'little')
    return decrypted[4:dataLen]


def create_local_key(passcode, salt):
    hashKey = hashlib.sha512(salt)
    hashKey.update(passcode)
    hashKey.update(salt)

    iterCount = 100000 if passcode else 1
    dst = hashlib.pbkdf2_hmac("sha512", hashKey.digest(),
                              salt, iterCount, 256)
    return bytearray(dst)

def storage_file_read(path, key):
    with open(path, 'rb') as f:
        if f.read(4) != b'TDEF':
            print(f"wrong key type at {path}")
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
        dst = ctr128_encrypt(
            src, self.key, self.block_index, self.iv
        )
        self.block_index += len(src) // 16
        return dst

def process_file(path):
    if path.is_file() and path.parent != cache and path.name not in ['version', 'binlog']:
        print('Decrypting', path)
        data = storage_file_read(path, local_key)
        if data is not None:
            mime = magic.from_buffer(data, mime=True)
            ext = mime.split('/')[1] # mimetypes не может определить разрешение у webp
            if ext == "octet-stream":
                ext = ".bin"
                if not args.unknown:
                    return
            elif ext == "x-gzip":
                ext = ".gz"
                if not args.unknown:
                    return
            else:
                ext = '.' + ext

            timestamp = os.path.getmtime(path)
            if args.directories:
                newf = out / path.relative_to(cache)
                newf.parent.mkdir(parents=True, exist_ok=True)
            else:
                newf = out
                newf = newf / path.name

            newf = newf.with_suffix(ext)
            #print(newf)
            with open(newf, 'wb') as f:
                f.write(data)
            os.utime(newf, (timestamp, timestamp))

parser = argparse.ArgumentParser()
parser.add_argument('-s', "--single", action='store_true', help='Один поток')
parser.add_argument('-d', "--directories", action='store_true', help='Создать структуру папок')
parser.add_argument('-o', "--output", default="out", help='Выходная папка')
parser.add_argument('-k', "--key", default=None, help=r"Адрес к ключу, по умолчанию %appdata%/Telegram Desktop/tdata/key_datas")
parser.add_argument('-c', "--cache", default=None, help="Путь к зашифрованным файлам")
parser.add_argument('-u', "--unknown", action='store_true', help="Сохранять неизвестные файлы")
args = parser.parse_args()

out = Path(args.output)
local_key = None
if not args.key:
    local_key = read_key(Path(os.getenv("APPDATA") / Path("Telegram Desktop/tdata/key_datas")))
else:
    local_key = read_key(Path(args.key))

cache = None
if not args.cache:
    cache = Path(os.getenv("APPDATA")) / Path('Telegram Desktop/tdata/user_data/cache').resolve()
else:
    cache = Path(args.cache)

#if not out.is_absolute():
#    out = Path.joinpath(Path.cwd(), out)
out.mkdir(parents=True, exist_ok=True)

if args.single:
    for i in cache.rglob('*'):
        process_file(i)
else:
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(process_file, cache.rglob('*'))


