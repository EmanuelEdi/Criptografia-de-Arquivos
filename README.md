# Criptografia de Arquivos com Interface Gráfica

Este projeto implementa um aplicativo de criptografia de arquivos com interface gráfica, utilizando diferentes algoritmos de criptografia como Fernet, AES e RSA, com compactação opcional e verificação de integridade.

##Execução
Clone o repositório: git clone https://github.com/seu-usuario/criptografia-de-arquivos.git
Gere as chaves de criptografia executando o script gerar_chave.py.
Execute o aplicativo: python criptografia.py

##Uso
Selecione o arquivo: Clique no botão "Procurar" para escolher o arquivo que deseja criptografar ou descriptografar.
Escolha o algoritmo: Selecione o algoritmo de criptografia desejado (Fernet, AES ou RSA) no menu suspenso.
Insira a senha (AES): Se você escolher o algoritmo AES, insira a senha no campo "Senha (AES)".
Compactar arquivo: Marque a opção "Compactar" para compactar o arquivo antes da criptografia.
Criptografar/Descriptografar: Clique no botão "Criptografar" ou "Descriptografar" para iniciar o processo.

##Contribuição
Contribuições são bem-vindas! Sinta-se à vontade para abrir problemas ou enviar solicitações de pull.

## Funcionalidades

*   **Criptografia e descriptografia de arquivos:** Suporta os algoritmos Fernet, AES e RSA.
*   **Compactação de arquivos:** Utiliza zlib para compactar arquivos antes da criptografia, reduzindo o tamanho e melhorando a eficiência.
*   **Verificação de integridade:** Gera e verifica hashes SHA-256 para garantir que os arquivos não foram alterados durante o processo.
*   **Proteção de chaves:** Permite proteger a chave privada RSA com uma senha.
*   **Interface gráfica amigável:** Desenvolvida com PyQt5, oferece uma interface intuitiva para interagir com as funcionalidades do aplicativo.
*   **Barra de progresso:** Exibe o andamento da criptografia e descriptografia, especialmente útil para arquivos grandes.
*   **Threads:** Executa as operações de criptografia e descriptografia em threads separadas, evitando que a interface gráfica trave.
*   **Tratamento de erros:** Implementa tratamento de erros robusto para lidar com diferentes tipos de exceções e fornecer mensagens de erro claras e informativas.

## Dependências

*   Python 3.6 ou superior
*   PyQt5
*   pycryptodome
*   bcrypt
*   cryptography

**Instalação das dependências:**

```bash
pip install PyQt5 pycryptodome bcrypt cryptography
'''
Execução
Clone o repositório: git clone https://github.com/seu-usuario/criptografia-de-arquivos.git
Gere as chaves de criptografia executando o script gerar_chave.py.
Execute o aplicativo: python criptografia.py
Uso
Selecione o arquivo: Clique no botão "Procurar" para escolher o arquivo que deseja criptografar ou descriptografar.
Escolha o algoritmo: Selecione o algoritmo de criptografia desejado (Fernet, AES ou RSA) no menu suspenso.
Insira a senha (AES): Se você escolher o algoritmo AES, insira a senha no campo "Senha (AES)".
Compactar arquivo: Marque a opção "Compactar" para compactar o arquivo antes da criptografia.
Criptografar/Descriptografar: Clique no botão "Criptografar" ou "Descriptografar" para iniciar o processo.
Contribuição
Contribuições são bem-vindas! Sinta-se à vontade para abrir problemas ou enviar solicitações de pull.
