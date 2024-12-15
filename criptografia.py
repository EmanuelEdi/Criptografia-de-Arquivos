import sys
import os
import hashlib
import zlib
import base64
import subprocess

from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, 
                             QPushButton, QFileDialog, QComboBox, QCheckBox,
                             QVBoxLayout, QHBoxLayout, QMessageBox)

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import bcrypt

def instalar_bibliotecas():
    """
    Instala as bibliotecas necessárias caso elas não estejam presentes.
    """
    try:
        import cryptography
        from Crypto.Cipher import AES
        import bcrypt
    except ImportError:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'cryptography'])
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome'])
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'bcrypt'])

# Instala as bibliotecas se necessário
instalar_bibliotecas()

# --- Funções de criptografia ---

def gerar_chave_fernet():
    """
    Gera uma nova chave de criptografia Fernet e a salva em um arquivo.
    """
    chave = Fernet.generate_key()
    with open("chave.key", "wb") as arquivo_chave:
        arquivo_chave.write(chave)

def gerar_chave_aes(senha):
    """
    Gera uma chave AES a partir de uma senha.
    """
    senha = senha.encode()
    salt = b'\x8c\xf2\xfa\x13\x15\x99H\x12\xa3\x18\x89\x9a\x98\x03\xfc'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    chave = base64.urlsafe_b64encode(kdf.derive(senha))
    return chave

def gerar_chaves_rsa():
    """
    Gera um par de chaves RSA (pública e privada).
    """
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    chave_publica = chave_privada.public_key()
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

def criptografar_fernet(nome_arquivo, chave):
    """
    Criptografa um arquivo usando Fernet.
    """
    try:
        f = Fernet(chave)
        with open(nome_arquivo, "rb") as arquivo:
            dados_arquivo = arquivo.read()
        dados_criptografados = f.encrypt(dados_arquivo)
        with open(nome_arquivo, "wb") as arquivo:
            arquivo.write(dados_criptografados)
    except Exception as e:
        raise Exception(f"Erro ao criptografar com Fernet: {e}")

def descriptografar_fernet(nome_arquivo, chave):
    """
    Descriptografa um arquivo usando Fernet.
    """
    try:
        f = Fernet(chave)
        with open(nome_arquivo, "rb") as arquivo:
            dados_criptografados = arquivo.read()
        dados_descriptografados = f.decrypt(dados_criptografados)
        with open(nome_arquivo, "wb") as arquivo:
            arquivo.write(dados_descriptografados)
    except Exception as e:
        raise Exception(f"Erro ao descriptografar com Fernet: {e}")

def criptografar_aes(nome_arquivo, chave):
    """
    Criptografa um arquivo usando AES.
    """
    try:
        cipher = AES.new(chave, AES.MODE_EAX)
        with open(nome_arquivo, "rb") as arquivo:
            dados_arquivo = arquivo.read()
        ciphertext, tag = cipher.encrypt_and_digest(dados_arquivo)
        with open(nome_arquivo, "wb") as arquivo:
            [ arquivo.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    except Exception as e:
        raise Exception(f"Erro ao criptografar com AES: {e}")

def descriptografar_aes(nome_arquivo, chave):
    """
    Descriptografa um arquivo usando AES.
    """
    try:
        with open(nome_arquivo, "rb") as arquivo:
            nonce, tag, ciphertext = [ arquivo.read(x) for x in (16, 16, -1) ]
        cipher = AES.new(chave, AES.MODE_EAX, nonce)
        dados_descriptografados = cipher.decrypt_and_verify(ciphertext, tag)
        with open(nome_arquivo, "wb") as arquivo:
            arquivo.write(dados_descriptografados)
    except Exception as e:
        raise Exception(f"Erro ao descriptografar com AES: {e}")

def criptografar_rsa(nome_arquivo, chave_publica):
    """
    Criptografa um arquivo usando RSA.
    """
    try:
        with open(nome_arquivo, "rb") as f:
            dados = f.read()
        with open(chave_publica, "rb") as key_file:
            chave_publica = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        dados_criptografados = chave_publica.encrypt(
            dados,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(nome_arquivo, "wb") as f:
            f.write(dados_criptografados)
    except Exception as e:
        raise Exception(f"Erro ao criptografar com RSA: {e}")


def descriptografar_rsa(nome_arquivo, chave_privada):
    """
    Descriptografa um arquivo usando RSA.
    """
    try:
        with open(nome_arquivo, "rb") as f:
            dados_criptografados = f.read()
        with open(chave_privada, "rb") as key_file:
            chave_privada = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        dados = chave_privada.decrypt(
            dados_criptografados,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(nome_arquivo, "wb") as f:
            f.write(dados)
    except Exception as e:
        raise Exception(f"Erro ao descriptografar com RSA: {e}")


# --- Funções auxiliares ---

def compactar(dados):
    """
    Compacta dados usando zlib.
    """
    try:
        return zlib.compress(dados)
    except Exception as e:
        raise Exception(f"Erro ao compactar: {e}")

def descompactar(dados_compactados):
    """
    Descompacta dados usando zlib.
    """
    try:
        return zlib.decompress(dados_compactados)
    except Exception as e:
        raise Exception(f"Erro ao descompactar: {e}")

def gerar_hash(nome_arquivo):
    """
    Gera o hash SHA-256 de um arquivo.
    """
    try:
        hasher = hashlib.sha256()
        with open(nome_arquivo, "rb") as arquivo:
            while True:
                pedaço = arquivo.read(4096)
                if not pedaço:
                    break
                hasher.update(pedaço)
        return hasher.hexdigest()
    except Exception as e:
        raise Exception(f"Erro ao gerar hash: {e}")

def verificar_integridade(nome_arquivo, hash_original):
    """
    Verifica a integridade de um arquivo comparando seu hash com o hash original.
    """
    try:
        hash_atual = gerar_hash(nome_arquivo)
        return hash_atual == hash_original
    except Exception as e:
        raise Exception(f"Erro ao verificar integridade: {e}")

def gerar_hash_senha(senha):
    """
    Gera um hash da senha usando bcrypt.
    """
    try:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(senha.encode(), salt)
        return hashed_password
    except Exception as e:
        raise Exception(f"Erro ao gerar hash da senha: {e}")

def verificar_senha(senha, hashed_password):
    """
    Verifica se a senha fornecida corresponde ao hash.
    """
    try:
        return bcrypt.checkpw(senha.encode(), hashed_password)
    except Exception as e:
        raise Exception(f"Erro ao verificar senha: {e}")

# --- Classe da interface gráfica ---

class CriptografiaGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Criptografia de Arquivos')

        # Widgets
        self.lbl_arquivo = QLabel('Arquivo:')
        self.txt_arquivo = QLineEdit()
        self.btn_procurar = QPushButton('Procurar')
        self.lbl_algoritmo = QLabel('Algoritmo:')
        self.cb_algoritmo = QComboBox()
        self.cb_algoritmo.addItems(["Fernet", "AES", "RSA"])
        self.lbl_senha = QLabel('Senha (AES):')
        self.txt_senha = QLineEdit()
        self.txt_senha.setEchoMode(QLineEdit.Password)
        self.chk_compactar = QCheckBox('Compactar')
        self.btn_criptografar = QPushButton('Criptografar')
        self.btn_descriptografar = QPushButton('Descriptografar')

        # Layouts
        hbox_arquivo = QHBoxLayout()
        hbox_arquivo.addWidget(self.lbl_arquivo)
        hbox_arquivo.addWidget(self.txt_arquivo)
        hbox_arquivo.addWidget(self.btn_procurar)

        vbox = QVBoxLayout()
        vbox.addLayout(hbox_arquivo)
        vbox.addWidget(self.lbl_algoritmo)
        vbox.addWidget(self.cb_algoritmo)
        vbox.addWidget(self.lbl_senha)
        vbox.addWidget(self.txt_senha)
        vbox.addWidget(self.chk_compactar)
        vbox.addWidget(self.btn_criptografar)
        vbox.addWidget(self.btn_descriptografar)

        self.setLayout(vbox)

        # Conexões
        self.btn_procurar.clicked.connect(self.procurarArquivo)
        self.btn_criptografar.clicked.connect(self.criptografarArquivo)
        self.btn_descriptografar.clicked.connect(self.descriptografarArquivo)

        # Inicialização
        gerar_chave_fernet()
        gerar_chaves_rsa()

    def procurarArquivo(self):
        try:
            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog
            fileName, _ = QFileDialog.getOpenFileName(self,"Selecione o arquivo", "","All Files (*);;Text Files (*.txt)", options=options)
            if fileName:
                self.txt_arquivo.setText(fileName)
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao selecionar o arquivo: {e}")

    def criptografarArquivo(self):
        try:
            nome_arquivo = self.txt_arquivo.text()
            if not nome_arquivo:
                raise ValueError("Selecione um arquivo primeiro.")

            algoritmo = self.cb_algoritmo.currentText()
            if algoritmo == "Fernet":
                chave = open("chave.key", "rb").read()
                criptografar_fernet(nome_arquivo, chave)
            elif algoritmo == "AES":
                senha = self.txt_senha.text()
                if not senha:
                    raise ValueError("Digite a senha para criptografia AES.")
                chave = gerar_chave_aes(senha)
                criptografar_aes(nome_arquivo, chave)
            elif algoritmo == "RSA":
                criptografar_rsa(nome_arquivo, "chave_publica.pem")
            else:
                raise ValueError("Algoritmo de criptografia inválido.")

            if self.chk_compactar.isChecked():
                with open(nome_arquivo, "rb") as arquivo:
                    dados = arquivo.read()
                dados_compactados = compactar(dados)
                with open(nome_arquivo, "wb") as arquivo:
                    arquivo.write(dados_compactados)

            QMessageBox.information(self, "Sucesso", "Arquivo criptografado com sucesso!")
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))

    def descriptografarArquivo(self):
        try:
            nome_arquivo = self.txt_arquivo.text()
            if not nome_arquivo:
                raise ValueError("Selecione um arquivo primeiro.")

            algoritmo = self.cb_algoritmo.currentText()
            if algoritmo == "Fernet":
                chave = open("chave.key", "rb").read()
                descriptografar_fernet(nome_arquivo, chave)
            elif algoritmo == "AES":
                senha = self.txt_senha.text()
                if not senha:
                    raise ValueError("Digite a senha para descriptografia AES.")
                chave = gerar_chave_aes(senha)
                descriptografar_aes(nome_arquivo, chave)
            elif algoritmo == "RSA":
                descriptografar_rsa(nome_arquivo, "chave_privada.pem")
            else:
                raise ValueError("Algoritmo de descriptografia inválido.")

            if self.chk_compactar.isChecked():
                with open(nome_arquivo, "rb") as arquivo:
                    dados_compactados = arquivo.read()
                dados = descompactar(dados_compactados)
                with open(nome_arquivo, "wb") as arquivo:
                    arquivo.write(dados)

            QMessageBox.information(self, "Sucesso", "Arquivo descriptografado com sucesso!")
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = CriptografiaGUI()
    ex.show()
    sys.exit(app.exec_())