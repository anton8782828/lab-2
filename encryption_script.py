
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
import os

# Введіть свої дані для шифрування
data = b"Secret message to encrypt"

# === Генерація симетричного ключа через PBKDF2 ===
password = b'my_strong_password'
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = kdf.derive(password)

# === Шифрування симетричним AES ===
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()

# Додавання відступів (PKCS7)
padder = padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()

encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# === Генерація HMAC для перевірки цілісності ===
h = hmac.HMAC(key, hashes.SHA256())
h.update(encrypted_data)
mac = h.finalize()

# === Дешифрування AES ===
decryptor = cipher.decryptor()
decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

# Видалення відступів
unpadder = padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

# Перевірка HMAC
h_verify = hmac.HMAC(key, hashes.SHA256())
h_verify.update(encrypted_data)
h_verify.verify(mac)

# === Генерація асиметричних ключів ===
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Серіалізація ключів
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# === Шифрування за допомогою відкритого ключа ===
encrypted_data_asym = public_key.encrypt(
    decrypted_data,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# === Цифровий підпис ===
signature = private_key.sign(
    decrypted_data,
    asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# === Розшифрування за допомогою закритого ключа ===
decrypted_data_asym = private_key.decrypt(
    encrypted_data_asym,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# === Перевірка підпису ===
public_key.verify(
    signature,
    decrypted_data,
    asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("Original data:", data)
print("Decrypted data:", decrypted_data)
print("Decrypted asymmetric data:", decrypted_data_asym)
