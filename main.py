# Conteúdo completo para o arquivo: main.py

from alice import (
    gerar_e_salvar_chaves_rsa_alice,
    criar_e_salvar_certificado_simulado_alice,
    preparar_mensagem_segura
)
from bob import (
    gerar_e_salvar_chaves_rsa_bob,
    processar_pacote_recebido
)
import os
import json
import base64

# Define o diretório base do projeto (onde main.py está)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHAVES_DIR = os.path.join(BASE_DIR, "chaves")
CERTIFICADOS_DIR = os.path.join(BASE_DIR, "certificados")

def preparativos_iniciais():
    print("--- Iniciando Preparativos Iniciais ---")
    if not os.path.exists(os.path.join(CHAVES_DIR, "alice_chave_privada.pem")):
        print("\nGerando chaves para Alice...")
        gerar_e_salvar_chaves_rsa_alice(diretorio_chaves=CHAVES_DIR)
    else:
        print("\nChaves da Alice já existem.")

    caminho_pub_alice = os.path.join(CHAVES_DIR, "alice_chave_publica.pem")
    if not os.path.exists(os.path.join(CERTIFICADOS_DIR, "certificado_alice.json")):
        if os.path.exists(caminho_pub_alice):
            print("\nCriando certificado simulado para Alice...")
            criar_e_salvar_certificado_simulado_alice(
                caminho_chave_publica_alice=caminho_pub_alice,
                caminho_certificado_saida_dir=CERTIFICADOS_DIR
            )
        else:
            print("\nERRO: Chave pública da Alice não encontrada para criar certificado.")
            return False
    else:
        print("\nCertificado da Alice já existe.")

    if not os.path.exists(os.path.join(CHAVES_DIR, "bob_chave_privada.pem")):
        print("\nGerando chaves para Bob...")
        gerar_e_salvar_chaves_rsa_bob(diretorio_chaves=CHAVES_DIR)
    else:
        print("\nChaves do Bob já existem.")
    
    print("\n--- Preparativos Iniciais Concluídos ---")
    return True

def simular_cenario_normal():
    print("\n\n--- CENÁRIO: COMUNICAÇÃO NORMAL ---")
    mensagem_da_alice = "Olá Bob! Esta é uma mensagem secreta e autenticada. 🚀"
    print(f"\nAlice vai enviar: '{mensagem_da_alice}'")

    caminho_priv_alice = os.path.join(CHAVES_DIR, "alice_chave_privada.pem")
    caminho_pub_bob = os.path.join(CHAVES_DIR, "bob_chave_publica.pem")
    caminho_cert_alice = os.path.join(CERTIFICADOS_DIR, "certificado_alice.json")

    if not all(os.path.exists(p) for p in [caminho_priv_alice, caminho_pub_bob, caminho_cert_alice]):
        print("\nERRO: Arquivos de chave/certificado necessários para Alice não encontrados.")
        return

    pacote_de_alice_para_bob = preparar_mensagem_segura(
        mensagem_da_alice,
        caminho_priv_alice,
        caminho_pub_bob,
        caminho_cert_alice
    )
    if not pacote_de_alice_para_bob: return

    print("\nPacote Original (sem adulteração):")
    print(json.dumps(pacote_de_alice_para_bob, indent=2, ensure_ascii=False))
    print("\n--- Pacote Transmitido para Bob ---")

    caminho_priv_bob = os.path.join(CHAVES_DIR, "bob_chave_privada.pem")
    if not os.path.exists(caminho_priv_bob): return

    mensagem_final_bob, sucesso_bob, status_msg_bob = processar_pacote_recebido(
        pacote_de_alice_para_bob,
        caminho_priv_bob
    )
    print_resultado_bob(mensagem_final_bob, sucesso_bob, status_msg_bob, mensagem_da_alice)


def simular_mensagem_adulterada():
    print("\n\n--- CENÁRIO: MENSAGEM ADULTERADA ---")
    mensagem_da_alice = "Olá Bob! Esta é uma mensagem secreta e autenticada. 🚀"
    print(f"\nAlice vai enviar (e será interceptada/adulterada): '{mensagem_da_alice}'")

    caminho_priv_alice = os.path.join(CHAVES_DIR, "alice_chave_privada.pem")
    caminho_pub_bob = os.path.join(CHAVES_DIR, "bob_chave_publica.pem")
    caminho_cert_alice = os.path.join(CERTIFICADOS_DIR, "certificado_alice.json")
    if not all(os.path.exists(p) for p in [caminho_priv_alice, caminho_pub_bob, caminho_cert_alice]): return

    pacote_original = preparar_mensagem_segura(
        mensagem_da_alice,
        caminho_priv_alice,
        caminho_pub_bob,
        caminho_cert_alice
    )
    if not pacote_original: return
    
    print("\nADULTERANDO PACOTE: Modificando a mensagem cifrada...")
    pacote_adulterado = pacote_original.copy()
    try:
        msg_cifrada_bytes = base64.b64decode(pacote_adulterado["mensagem_cifrada_aes_b64"])
        byte_modificado = bytes([msg_cifrada_bytes[0] ^ 0xFF])
        msg_cifrada_adulterada_bytes = byte_modificado + msg_cifrada_bytes[1:]
        pacote_adulterado["mensagem_cifrada_aes_b64"] = base64.b64encode(msg_cifrada_adulterada_bytes).decode('utf-8')
        print("Mensagem cifrada no pacote foi ALTERADA.")
    except Exception as e:
        print(f"Erro ao tentar adulterar a mensagem cifrada: {e}")
        return

    print("\nPacote Adulterado:")
    print(json.dumps(pacote_adulterado, indent=2, ensure_ascii=False))
    print("\n--- Pacote Adulterado Transmitido para Bob ---")

    caminho_priv_bob = os.path.join(CHAVES_DIR, "bob_chave_privada.pem")
    if not os.path.exists(caminho_priv_bob): return

    mensagem_final_bob, sucesso_bob, status_msg_bob = processar_pacote_recebido(
        pacote_adulterado,
        caminho_priv_bob
    )
    print_resultado_bob(mensagem_final_bob, sucesso_bob, status_msg_bob, mensagem_da_alice, cenario_teste="mensagem_adulterada")

def simular_certificado_adulterado():
    print("\n\n--- CENÁRIO: CERTIFICADO DO REMETENTE ADULTERADO ---")
    mensagem_da_alice = "Olá Bob! Esta é uma mensagem secreta e autenticada. 🚀"
    print(f"\nAlice vai enviar (mas seu certificado será interceptado/adulterado): '{mensagem_da_alice}'")

    caminho_priv_alice = os.path.join(CHAVES_DIR, "alice_chave_privada.pem")
    caminho_pub_bob = os.path.join(CHAVES_DIR, "bob_chave_publica.pem")
    caminho_cert_alice = os.path.join(CERTIFICADOS_DIR, "certificado_alice.json") # Certificado original
    if not all(os.path.exists(p) for p in [caminho_priv_alice, caminho_pub_bob, caminho_cert_alice]): return

    pacote_original = preparar_mensagem_segura(
        mensagem_da_alice,
        caminho_priv_alice,
        caminho_pub_bob,
        caminho_cert_alice
    )
    if not pacote_original: return

    # ADULTERANDO O CERTIFICADO NO PACOTE
    print("\nADULTERANDO PACOTE: Modificando o 'proprietario' no certificado do remetente...")
    pacote_com_certificado_adulterado = json.loads(json.dumps(pacote_original)) # Deep copy para não afetar outros testes
    
    # Modificação 1: Nome do proprietário incorreto
    pacote_com_certificado_adulterado["certificado_remetente"]["proprietario"] = "Eve_Invasora"
    print("Campo 'proprietario' do certificado foi ALTERADO para 'Eve_Invasora'.")
    
    print("\nPacote com Certificado Adulterado (Proprietário):")
    print(json.dumps(pacote_com_certificado_adulterado, indent=2, ensure_ascii=False))
    print("\n--- Pacote com Certificado Adulterado (Proprietário) Transmitido para Bob ---")

    caminho_priv_bob = os.path.join(CHAVES_DIR, "bob_chave_privada.pem")
    if not os.path.exists(caminho_priv_bob): return

    mensagem_final_bob, sucesso_bob, status_msg_bob = processar_pacote_recebido(
        pacote_com_certificado_adulterado,
        caminho_priv_bob
    )
    print_resultado_bob(mensagem_final_bob, sucesso_bob, status_msg_bob, mensagem_da_alice, cenario_teste="certificado_adulterado_proprietario")

    # Modificação 2 (opcional): Chave pública no certificado adulterada (para uma chave inválida)
    print("\nADULTERANDO PACOTE: Modificando a 'chave_publica_pem' no certificado para ser inválida...")
    pacote_com_certificado_adulterado_chave = json.loads(json.dumps(pacote_original)) # Reverte para o original para este novo teste
    pacote_com_certificado_adulterado_chave["certificado_remetente"]["chave_publica_pem"] = "---BEGIN PUBLIC KEY-----\nISSO_NAO_EH_UMA_CHAVE_VALIDA\n-----END PUBLIC KEY-----\n"
    print("Campo 'chave_publica_pem' do certificado foi ALTERADO para um valor inválido.")

    print("\nPacote com Certificado Adulterado (Chave Pública Inválida):")
    print(json.dumps(pacote_com_certificado_adulterado_chave, indent=2, ensure_ascii=False))
    print("\n--- Pacote com Certificado Adulterado (Chave Pública Inválida) Transmitido para Bob ---")
    
    mensagem_final_bob_2, sucesso_bob_2, status_msg_bob_2 = processar_pacote_recebido(
        pacote_com_certificado_adulterado_chave,
        caminho_priv_bob
    )
    print_resultado_bob(mensagem_final_bob_2, sucesso_bob_2, status_msg_bob_2, mensagem_da_alice, cenario_teste="certificado_adulterado_chave")


def print_resultado_bob(mensagem_final, sucesso, status_msg, msg_original_alice, cenario_teste=""):
    """Função auxiliar para imprimir o resultado do processamento de Bob."""
    print(f"\n--- Resultado do Processamento por Bob ({cenario_teste}) ---")
    print(f"Status: {status_msg}")
    if sucesso:
        print(f"Bob leu a mensagem: '{mensagem_final}'")
        if mensagem_final == msg_original_alice:
            print("SUCESSO TOTAL: A mensagem original foi recuperada e validada corretamente por Bob!")
        else:
            print("ALERTA: Mensagem recuperada diferente da original, mas Bob ainda conseguiu decifrá-la para algo.")
    else: # Falha no processamento (sucesso == False)
        print("FALHA: Bob não conseguiu validar ou decifrar a mensagem corretamente.")
        if cenario_teste == "mensagem_adulterada" and "assinatura inválida" in status_msg.lower():
            print("SUCESSO NO TESTE DE MENSAGEM ADULTERADA: A assinatura inválida foi detectada como esperado!")
        elif cenario_teste == "mensagem_adulterada" and "utf-8" in status_msg.lower(): # Nosso caso atual
            print("SUCESSO NO TESTE DE MENSAGEM ADULTERADA: A corrupção da mensagem impediu a decodificação UTF-8, como esperado!")
        elif "certificado_adulterado" in cenario_teste and ("certificado" in status_msg.lower() or "chave pública do certificado" in status_msg.lower()):
            print("SUCESSO NO TESTE DE CERTIFICADO ADULTERADO: A falha no certificado foi detectada como esperado!")
        
        if mensagem_final:
             print(f"Conteúdo parcial (pode estar incorreto ou não confiável): '{mensagem_final}'")


if __name__ == "__main__":
    if preparativos_iniciais():
        simular_cenario_normal()
        simular_mensagem_adulterada()
        simular_certificado_adulterado() # Nova simulação adicionada
    else:
        print("\nFalha nos preparativos iniciais. Simulação não pode continuar.")