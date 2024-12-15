from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def gerar_chave_fernet():
    """
    Gera uma nova chave de criptografia Fernet e a salva em um arquivo.
    """
    chave = Fernet.generate_key()
    with open("chave.key", "wb") as arquivo_chave:
        arquivo_chave.write(chave)

def gerar_chaves_rsa(senha=None):
    """
    Gera um par de chaves RSA (pública e privada).
    A chave privada pode ser protegida com senha (opcional).
    """
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    chave_publica = chave_privada.public_key()

    if senha:
        senha = senha.encode()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        chave_criptografia = kdf.derive(senha)
        
        with open("chave_privada.pem", "wb") as f:
            f.write(chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(chave_criptografia)
            ))
        with open("chave_publica.pem", "wb") as f:
            f.write(chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        with open("chave_privada.pem", "wb") as f:
            f.write(chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("chave_publica.pem", "wb") as f:
            f.write(chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

# Gera as chaves ao executar o script
gerar_chave_fernet()

# Solicita a senha para proteger a chave privada RSA
senha_rsa = input("Digite uma senha para proteger a chave privada RSA (opcional): ")
if senha_rsa:
    gerar_chaves_rsa(senha_rsa)
else:
    gerar_chaves_rsa()