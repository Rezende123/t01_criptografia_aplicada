"""Descriptografa um arquivo gerado por criptografar.py (AES-GCM).

A chave deve ser a mesma usada na criptografia (hex de 16, 24 ou 32 bytes).
Se a chave estiver errada ou o arquivo tiver sido alterado, a verificação
da tag de autenticação falha (InvalidTag) e nenhum dado é gravado.

Ela pode ser passada direto (--chave) ou lida de um arquivo (--arquivo-chave).

Exemplos:
    python descriptografar.py hino_bahia.txt.enc --arquivo-chave chave.txt -o hino_recuperado.txt
    python descriptografar.py hino_bahia.txt.enc --chave <hex> -o hino_recuperado.txt
"""

import argparse
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGICO = b"AGCM"
VERSAO = 1
TAM_NONCE = 12
TAM_TAG = 16


def ler_chave(chave_hex: str) -> bytes:
    try:
        chave = bytes.fromhex(chave_hex.strip())
    except ValueError:
        sys.exit("Erro: a chave deve estar em hexadecimal (0-9, a-f).")
    if len(chave) not in (16, 24, 32):
        sys.exit(
            f"Erro: a chave tem {len(chave)} bytes; use 16, 24 ou 32 bytes "
            "(32, 48 ou 64 caracteres hex)."
        )
    return chave


def ler_arquivo_chave(caminho: str) -> str:
    # Aceita UTF-8 (com ou sem BOM) e UTF-16, que é o padrão do ">" e do
    # Out-File no Windows PowerShell 5.1.
    try:
        with open(caminho, "rb") as f:
            bruto = f.read()
    except OSError as e:
        sys.exit(f"Erro ao ler o arquivo de chave '{caminho}': {e}")
    codificacao = "utf-16" if bruto[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    try:
        return bruto.decode(codificacao)
    except UnicodeDecodeError:
        sys.exit(f"Erro: o arquivo de chave '{caminho}' não é um texto válido "
                 "(salve-o como UTF-8 ou UTF-16 contendo apenas o hex da chave).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Descriptografa um arquivo AES-GCM.")
    parser.add_argument("entrada", help="arquivo criptografado (.enc)")
    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument("-k", "--chave", help="chave em hex (16, 24 ou 32 bytes)")
    grupo.add_argument("-f", "--arquivo-chave",
                       help="arquivo de texto contendo a chave em hex")
    parser.add_argument("-o", "--saida",
                        help="arquivo de saída (padrão: <entrada> sem .enc, ou <entrada>.dec)")
    args = parser.parse_args()

    chave = ler_chave(args.chave or ler_arquivo_chave(args.arquivo_chave))
    if args.saida:
        saida = args.saida
    elif args.entrada.endswith(".enc"):
        saida = args.entrada[:-4]
    else:
        saida = args.entrada + ".dec"

    try:
        with open(args.entrada, "rb") as f:
            conteudo = f.read()
    except OSError as e:
        sys.exit(f"Erro ao ler '{args.entrada}': {e}")

    tam_cabecalho = len(MAGICO) + 1
    if len(conteudo) < tam_cabecalho + TAM_NONCE + TAM_TAG or conteudo[:4] != MAGICO:
        sys.exit("Erro: o arquivo não está no formato esperado (não foi gerado por criptografar.py).")
    if conteudo[4] != VERSAO:
        sys.exit(f"Erro: versão de formato não suportada ({conteudo[4]}).")

    cabecalho = conteudo[:tam_cabecalho]
    nonce = conteudo[tam_cabecalho:tam_cabecalho + TAM_NONCE]
    cifrado = conteudo[tam_cabecalho + TAM_NONCE:]

    try:
        dados = AESGCM(chave).decrypt(nonce, cifrado, cabecalho)
    except InvalidTag:
        sys.exit(
            "Erro: falha na autenticação (InvalidTag). A chave está incorreta "
            "ou o arquivo foi corrompido/adulterado. Nenhum arquivo foi gerado."
        )

    with open(saida, "wb") as f:
        f.write(dados)

    print(f"Arquivo descriptografado salvo em: {saida}")


if __name__ == "__main__":
    main()
