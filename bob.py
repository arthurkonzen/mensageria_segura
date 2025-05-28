# Conteúdo completo para o arquivo: bob.py

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding # Para o unpadding do AES
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature # Para capturar erro de assinatura inválida
import os
import json
import base64

# --- Função de Geração de Chaves (já existente) ---
def gerar_e_salvar_chaves_rsa_bob(diretorio_chaves="chaves"):
    if not os.path.exists(diretorio_chaves):
        os.makedirs(diretorio_chaves)
        print(f"Diretório '{diretorio_chaves}' criado.")
    chave_privada_bob = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    print("Chave privada do Bob gerada.")
    chave_publica_bob = chave_privada_bob.public_key()
    print("Chave pública do Bob obtida.")
    pem_chave_privada = chave_privada_bob.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    caminho_privada = os.path.join(diretorio_chaves, "bob_chave_privada.pem")
    with open(caminho_privada, "wb") as f:
        f.write(pem_chave_privada)
    print(f"Chave privada do Bob salva em: {caminho_privada}")
    pem_chave_publica = chave_publica_bob.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    caminho_publica = os.path.join(diretorio_chaves, "bob_chave_publica.pem")
    with open(caminho_publica, "wb") as f:
        f.write(pem_chave_publica)
    print(f"Chave pública do Bob salva em: {caminho_publica}")

# --- Novas Funções para Processar a Mensagem Recebida ---

def carregar_chave_privada_pem(caminho_arquivo):
    with open(caminho_arquivo, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # Se a chave estiver protegida por senha, forneça aqui
            backend=default_backend()
        )
    return private_key

def carregar_chave_publica_de_string_pem(pem_string):
    public_key = serialization.load_pem_public_key(
        pem_string.encode('utf-8'),
        backend=default_backend()
    )
    return public_key

def validar_certificado_simulado(certificado_dados):
    """
    Validação MUITO SIMPLES do certificado simulado.
    Em um cenário real, isso envolveria verificar a assinatura da AC, cadeia de confiança, CRLs, etc.
    """
    print("\n--- Bob: Validando Certificado do Remetente ---")
    if not certificado_dados:
        print("ERRO: Certificado não fornecido.")
        return None, "Certificado não fornecido."

    proprietario = certificado_dados.get("proprietario")
    chave_publica_pem = certificado_dados.get("chave_publica_pem")
    emissor = certificado_dados.get("emissor_simulado")

    # Exemplo de verificações simples:
    if proprietario != "Alice": # Poderia ser mais genérico
        print(f"ERRO: Proprietário do certificado '{proprietario}' não é o esperado ('Alice').")
        return None, "Proprietário do certificado inválido."
    if emissor != "MiniAC_Exemplo_DV": # Bob "confia" neste emissor simulado
        print(f"ERRO: Emissor do certificado '{emissor}' não é confiável.")
        return None, "Emissor do certificado não confiável."
    if not (chave_publica_pem and "-----BEGIN PUBLIC KEY-----" in chave_publica_pem):
        print("ERRO: Chave pública ausente ou mal formatada no certificado.")
        return None, "Chave pública no certificado inválida."

    # Validade (simples verificação de formato, não a data real neste exemplo)
    # Em um caso real, você compararia com a data atual.
    # from datetime import datetime
    # valido_de = datetime.strptime(certificado_dados.get("valido_de"), "%Y-%m-%d")
    # valido_ate = datetime.strptime(certificado_dados.get("valido_ate"), "%Y-%m-%d")
    # if not (valido_de <= datetime.now() <= valido_ate):
    # print("ERRO: Certificado expirado ou ainda não válido.")
    # return None, "Certificado fora do período de validade."

    print("Certificado simulado considerado válido (proprietário, emissor e formato da chave OK).")
    try:
        chave_publica_remetente = carregar_chave_publica_de_string_pem(chave_publica_pem)
        print("Chave pública do remetente extraída do certificado.")
        return chave_publica_remetente, "Certificado válido."
    except Exception as e:
        print(f"ERRO ao carregar chave pública do certificado: {e}")
        return None, f"Erro ao carregar chave pública do certificado: {e}"


def processar_pacote_recebido(pacote, caminho_chave_privada_bob):
    """
    Processa o pacote recebido de Alice:
    1. Valida o certificado.
    2. Decifra a chave simétrica.
    3. Decifra a mensagem.
    4. Verifica a assinatura.
    Retorna (mensagem_decifrada_str, status_bool, status_mensagem_str)
    """
    print("\n--- Bob: Processando Pacote Recebido ---")
    try:
        # Decodificar dados de Base64 para bytes
        mensagem_cifrada_aes = base64.b64decode(pacote["mensagem_cifrada_aes_b64"])
        iv_aes = base64.b64decode(pacote["iv_aes_b64"])
        chave_simetrica_cifrada_rsa = base64.b64decode(pacote["chave_simetrica_cifrada_rsa_b64"])
        assinatura_digital_recebida = base64.b64decode(pacote["assinatura_digital_b64"])
        certificado_remetente_dados = pacote["certificado_remetente"]
    except KeyError as e:
        return None, False, f"ERRO: Componente ausente no pacote: {e}"
    except Exception as e:
        return None, False, f"ERRO ao decodificar dados Base64 do pacote: {e}"

    # 1. Validar o Certificado Digital da Alice e extrair chave pública dela
    chave_publica_alice, status_cert = validar_certificado_simulado(certificado_remetente_dados)
    if not chave_publica_alice:
        return None, False, f"FALHA NA VALIDAÇÃO DO CERTIFICADO: {status_cert}"

    # Carregar chave privada de Bob
    try:
        chave_privada_bob_obj = carregar_chave_privada_pem(caminho_chave_privada_bob)
        print("Chave privada do Bob carregada.")
    except Exception as e:
        return None, False, f"ERRO ao carregar chave privada do Bob: {e}"

    # 2. Decifrar a Chave Simétrica com a Chave Privada do Bob (RSA)
    try:
        chave_simetrica_aes_decifrada = chave_privada_bob_obj.decrypt(
            chave_simetrica_cifrada_rsa,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Chave simétrica AES decifrada com sucesso: {chave_simetrica_aes_decifrada.hex()}")
    except Exception as e:
        return None, False, f"ERRO ao decifrar a chave simétrica AES: {e}"

    # 3. Decifrar a Mensagem com a Chave Simétrica (AES)
    try:
        cipher_aes = Cipher(algorithms.AES(chave_simetrica_aes_decifrada), modes.CBC(iv_aes), backend=default_backend())
        decryptor_aes = cipher_aes.decryptor()
        dados_com_padding_decifrados = decryptor_aes.update(mensagem_cifrada_aes) + decryptor_aes.finalize()

        # Remover padding PKCS7
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        mensagem_decifrada_bytes = unpadder.update(dados_com_padding_decifrados) + unpadder.finalize()
        mensagem_decifrada_str = mensagem_decifrada_bytes.decode('utf-8')
        print("Mensagem decifrada com AES.")
    except Exception as e:
        return None, False, f"ERRO ao decifrar a mensagem com AES: {e}"

    # 4. Calcular o Hash da Mensagem Decifrada (SHA-256)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(mensagem_decifrada_bytes) # Usar os bytes da mensagem decifrada
    hash_mensagem_calculado = digest.finalize()
    print(f"Hash da mensagem decifrada calculado por Bob: {hash_mensagem_calculado.hex()}")

    # 5. Verificar a Assinatura Digital com a Chave Pública da Alice (do certificado)
    try:
        chave_publica_alice.verify(
            assinatura_digital_recebida,
            hash_mensagem_calculado, # O hash que Bob calculou da mensagem que ele decifrou
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("ASSINATURA DIGITAL VÁLIDA! A mensagem é autêntica e íntegra.")
        print("--- Bob: Processamento Concluído com Sucesso ---")
        return mensagem_decifrada_str, True, "Mensagem processada com sucesso. Assinatura válida."
    except InvalidSignature:
        print("ERRO: ASSINATURA DIGITAL INVÁLIDA! A mensagem pode ter sido alterada ou não é da Alice.")
        return mensagem_decifrada_str, False, "FALHA NA VERIFICAÇÃO DA ASSINATURA: Assinatura inválida."
    except Exception as e:
        return mensagem_decifrada_str, False, f"ERRO ao verificar a assinatura: {e}"


# Bloco if __name__ == '__main__': (para testes diretos, se necessário)
if __name__ == '__main__':
    print("Executando testes de bob.py...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dir_chaves_teste_bob = os.path.join(script_dir, 'chaves')

    # Para testar bob.py diretamente, precisaríamos de um 'pacote' de exemplo.
    # Este teste é mais complexo de fazer isoladamente sem o fluxo do main.py.
    # Vamos apenas garantir que a geração de chaves do Bob funcione se chamada diretamente.
    if not os.path.exists(os.path.join(dir_chaves_teste_bob, "bob_chave_privada.pem")):
        print("Gerando chaves do Bob para teste...")
        gerar_e_salvar_chaves_rsa_bob(diretorio_chaves=dir_chaves_teste_bob)
    else:
        print("Chaves do Bob já existem (verificado para teste).")
    
    print("\nTestes básicos de bob.py concluídos (geração de chaves).")
    print("Para testar processar_pacote_recebido, execute main.py.")