# Conteúdo completo para o arquivo: alice.py

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json

# --- Funções de Geração de Chaves e Certificado (já existentes) ---
def gerar_e_salvar_chaves_rsa_alice(diretorio_chaves="chaves"):
    if not os.path.exists(diretorio_chaves):
        os.makedirs(diretorio_chaves)
        print(f"Diretório '{diretorio_chaves}' criado.")
    chave_privada_alice = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    print("Chave privada da Alice gerada.")
    chave_publica_alice = chave_privada_alice.public_key()
    print("Chave pública da Alice obtida.")
    pem_chave_privada = chave_privada_alice.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    caminho_privada = os.path.join(diretorio_chaves, "alice_chave_privada.pem")
    with open(caminho_privada, "wb") as f:
        f.write(pem_chave_privada)
    print(f"Chave privada da Alice salva em: {caminho_privada}")
    pem_chave_publica = chave_publica_alice.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    caminho_publica = os.path.join(diretorio_chaves, "alice_chave_publica.pem")
    with open(caminho_publica, "wb") as f:
        f.write(pem_chave_publica)
    print(f"Chave pública da Alice salva em: {caminho_publica}")

def criar_e_salvar_certificado_simulado_alice(caminho_chave_publica_alice, caminho_certificado_saida_dir="certificados"):
    if not os.path.exists(caminho_certificado_saida_dir):
        os.makedirs(caminho_certificado_saida_dir)
        print(f"Diretório '{caminho_certificado_saida_dir}' criado.")
    try:
        with open(caminho_chave_publica_alice, "rb") as f:
            chave_publica_pem = f.read().decode('utf-8')
    except FileNotFoundError:
        print(f"ERRO: Arquivo da chave pública da Alice não encontrado em {caminho_chave_publica_alice}")
        return
    dados_certificado_alice = {
        "proprietario": "Alice",
        "email": "alice@example.com",
        "chave_publica_pem": chave_publica_pem,
        "valido_de": "2025-01-01",
        "valido_ate": "2026-01-01",
        "emissor_simulado": "MiniAC_Exemplo_DV"
    }
    caminho_arquivo_certificado = os.path.join(caminho_certificado_saida_dir, "certificado_alice.json")
    with open(caminho_arquivo_certificado, "w") as f:
        json.dump(dados_certificado_alice, f, indent=4)
    print(f"Certificado simulado da Alice salvo em: {caminho_arquivo_certificado}")

# --- Novas Funções para Preparar a Mensagem ---

def carregar_chave_privada_pem(caminho_arquivo):
    with open(caminho_arquivo, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # Se a chave estiver protegida por senha, forneça aqui
            backend=default_backend()
        )
    return private_key

def carregar_chave_publica_pem(caminho_arquivo):
    with open(caminho_arquivo, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def preparar_mensagem_segura(mensagem_original_str, caminho_chave_privada_alice, caminho_chave_publica_bob, caminho_certificado_alice):
    """
    Prepara um pacote seguro contendo a mensagem criptografada,
    chave simétrica criptografada, assinatura e certificado.
    """
    print("\n--- Alice: Preparando Mensagem Segura ---")
    mensagem_original_bytes = mensagem_original_str.encode('utf-8')

    # 1. Gerar Hash da Mensagem (SHA-256)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(mensagem_original_bytes)
    hash_mensagem = digest.finalize()
    print(f"Hash da mensagem original (SHA-256) gerado: {hash_mensagem.hex()}")

    # 2. Gerar Chave Simétrica (AES) e IV (Vetor de Inicialização)
    chave_simetrica_aes = os.urandom(32)  # AES-256 (32 bytes)
    iv_aes = os.urandom(16)             # IV para AES CBC (16 bytes)
    print(f"Chave simétrica AES gerada: {chave_simetrica_aes.hex()}")
    print(f"IV para AES gerado: {iv_aes.hex()}")

    # 3. Criptografar a Mensagem com a Chave Simétrica (AES)
    cipher_aes = Cipher(algorithms.AES(chave_simetrica_aes), modes.CBC(iv_aes), backend=default_backend())
    encryptor_aes = cipher_aes.encryptor()
    # AES CBC requer que os dados sejam múltiplos do tamanho do bloco (16 bytes)
    # Adicionar padding PKCS7 manualmente se necessário (a biblioteca pode não fazer automaticamente para `update+finalize`)
    # Para simplificar, vamos garantir que a mensagem já tenha o padding ou usar uma biblioteca que o gerencie.
    # A biblioteca 'cryptography' para AES GCM faz isso de forma mais integrada, mas CBC é comum.
    # Para CBC com PKCS7 padding:
    from cryptography.hazmat.primitives import padding as sym_padding
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(mensagem_original_bytes) + padder.finalize()
    mensagem_cifrada_aes = encryptor_aes.update(padded_data) + encryptor_aes.finalize()
    print("Mensagem original criptografada com AES.")

    # Carregar chaves RSA
    try:
        chave_privada_alice_obj = carregar_chave_privada_pem(caminho_chave_privada_alice)
        chave_publica_bob_obj = carregar_chave_publica_pem(caminho_chave_publica_bob)
    except Exception as e:
        print(f"Erro ao carregar chaves RSA: {e}")
        return None
    print("Chaves RSA da Alice (privada) e Bob (pública) carregadas.")

    # 4. Criptografar a Chave Simétrica com a Chave Pública do Bob (RSA)
    chave_simetrica_cifrada_rsa = chave_publica_bob_obj.encrypt(
        chave_simetrica_aes, # A chave em si
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Chave simétrica AES criptografada com a chave pública do Bob (RSA).")

    # Precisamos enviar o IV junto com a chave simétrica cifrada, ou com a mensagem cifrada
    # Vamos criptografar o IV junto com a chave simétrica para simplificar o pacote.
    # Concatenamos IV + chave AES e criptografamos juntos, ou criptografamos separadamente.
    # Para este exemplo, vamos enviar o IV em claro, pois ele não precisa ser secreto, apenas único.
    # A chave simétrica cifrada já foi feita.

    # 5. Assinar o Hash da Mensagem com a Chave Privada da Alice (RSA)
    assinatura_digital = chave_privada_alice_obj.sign(
        hash_mensagem, # Assinando o hash da mensagem original
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Hash da mensagem assinado com a chave privada da Alice.")

    # 6. Carregar Certificado da Alice (simulado)
    try:
        with open(caminho_certificado_alice, 'r') as f:
            certificado_alice_dados = json.load(f)
    except Exception as e:
        print(f"Erro ao carregar o certificado da Alice: {e}")
        return None
    print("Certificado da Alice carregado.")

    # 7. Empacotar Tudo para Envio
    # Usaremos base64 para garantir que os dados binários sejam representados como strings no JSON
    import base64
    pacote_para_bob = {
        "mensagem_cifrada_aes_b64": base64.b64encode(mensagem_cifrada_aes).decode('utf-8'),
        "iv_aes_b64": base64.b64encode(iv_aes).decode('utf-8'), # IV precisa ser enviado para Bob
        "chave_simetrica_cifrada_rsa_b64": base64.b64encode(chave_simetrica_cifrada_rsa).decode('utf-8'),
        "assinatura_digital_b64": base64.b64encode(assinatura_digital).decode('utf-8'),
        "certificado_remetente": certificado_alice_dados
    }
    print("Pacote para Bob montado.")
    print("--- Alice: Preparação Concluída ---")
    return pacote_para_bob


# Bloco if __name__ == '__main__': (mantido para testes diretos, se necessário)
if __name__ == '__main__':
    print("Executando testes de alice.py...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dir_chaves_teste = os.path.join(script_dir, 'chaves')
    dir_cert_teste = os.path.join(script_dir, 'certificados')

    # Gerar chaves e certificado se não existirem (para teste)
    if not (os.path.exists(os.path.join(dir_chaves_teste, "alice_chave_privada.pem")) and \
            os.path.exists(os.path.join(dir_chaves_teste, "bob_chave_publica.pem"))):
        print("Gerando chaves para teste...")
        gerar_e_salvar_chaves_rsa_alice(diretorio_chaves=dir_chaves_teste)
        # Precisaria de uma função similar para Bob aqui, ou garantir que bob.py já as criou
        # Por simplicidade, assuma que bob.py foi executado ou chame aqui.
        # Vamos adicionar uma para Bob rapidamente para teste (idealmente seria em bob.py)
        if not os.path.exists(os.path.join(dir_chaves_teste, "bob_chave_publica.pem")):
             print("Chaves do Bob não encontradas para teste completo de alice.py, pule este teste ou gere-as.")

    caminho_pub_key_alice_teste = os.path.join(dir_chaves_teste, "alice_chave_publica.pem")
    if not os.path.exists(os.path.join(dir_cert_teste, "certificado_alice.json")):
        if os.path.exists(caminho_pub_key_alice_teste):
            print("Criando certificado para teste...")
            criar_e_salvar_certificado_simulado_alice(
                caminho_chave_publica_alice=caminho_pub_key_alice_teste,
                caminho_certificado_saida_dir=dir_cert_teste
            )
        else:
            print("Chave pública da Alice não encontrada, não foi possível criar certificado para teste.")

    # Testar preparação da mensagem
    print("\nTestando preparação de mensagem segura...")
    msg_teste = "Esta é uma mensagem de teste super secreta da Alice para o Bob!"
    path_priv_alice = os.path.join(dir_chaves_teste, "alice_chave_privada.pem")
    path_pub_bob = os.path.join(dir_chaves_teste, "bob_chave_publica.pem") # Bob precisa ter gerado suas chaves
    path_cert_alice = os.path.join(dir_cert_teste, "certificado_alice.json")

    if os.path.exists(path_priv_alice) and os.path.exists(path_pub_bob) and os.path.exists(path_cert_alice):
        pacote = preparar_mensagem_segura(msg_teste, path_priv_alice, path_pub_bob, path_cert_alice)
        if pacote:
            print("\nPacote de teste gerado (primeiros 100 chars de cada campo binário):")
            for k, v in pacote.items():
                if isinstance(v, str) and len(v) > 100 and k.endswith("_b64"):
                    print(f"  {k}: {v[:100]}...")
                elif isinstance(v, dict):
                     print(f"  {k}: {{...}} (certificado)")
                else:
                    print(f"  {k}: {v}")
    else:
        print("Arquivos necessários para teste (chaves/certificado) não encontrados. Pulei teste de preparação de mensagem.")

    print("\nTestes de alice.py concluídos.")