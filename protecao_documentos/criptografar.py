"""Criptografa um arquivo com AES-GCM (biblioteca cryptography).

Formato da chave: string hexadecimal de 16, 24 ou 32 bytes
(32, 48 ou 64 caracteres hex), correspondendo a AES-128, AES-192 ou AES-256.
A chave pode ser passada direto (--chave) ou lida de um arquivo de texto
(--arquivo-chave), o que evita deixá-la no histórico do terminal.

Formato do arquivo de saída:
    [4 bytes]  cabeçalho mágico b"AGCM"
    [1 byte ]  versão do formato (1)
    [12 bytes] nonce aleatório
    [N bytes]  texto cifrado + tag de autenticação (16 bytes no final)
O cabeçalho (mágico + versão) é passado como dado associado (AAD),
então qualquer alteração nele também é detectada na descriptografia.

Exemplos:
    python criptografar.py hino_bahia.txt --arquivo-chave chave.txt -o hino_bahia.txt.enc
    python criptografar.py hino_bahia.txt --chave <hex> -o hino_bahia.txt.enc
"""

import argparse
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGICO = b"AGCM"
VERSAO = 1
TAM_NONCE = 12


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
    parser = argparse.ArgumentParser(description="Criptografa um arquivo com AES-GCM.")
    parser.add_argument("entrada", nargs="?", help="arquivo a ser criptografado")
    grupo = parser.add_mutually_exclusive_group()
    grupo.add_argument("-k", "--chave", help="chave em hex (16, 24 ou 32 bytes)")
    grupo.add_argument("-f", "--arquivo-chave",
                       help="arquivo de texto contendo a chave em hex")
    parser.add_argument("-o", "--saida", help="arquivo de saída (padrão: <entrada>.enc)")
    args = parser.parse_args()

    if not args.entrada or not (args.chave or args.arquivo_chave):
        parser.error("informe o arquivo de entrada e --chave ou --arquivo-chave")

    chave = ler_chave(args.chave or ler_arquivo_chave(args.arquivo_chave))
    saida = args.saida or args.entrada + ".enc"

    try:
        with open(args.entrada, "rb") as f:
            dados = f.read()
    except OSError as e:
        sys.exit(f"Erro ao ler '{args.entrada}': {e}")

    cabecalho = MAGICO + bytes([VERSAO])
    nonce = os.urandom(TAM_NONCE)
    cifrado = AESGCM(chave).encrypt(nonce, dados, cabecalho)

    with open(saida, "wb") as f:
        f.write(cabecalho + nonce + cifrado)

    print(f"Arquivo criptografado salvo em: {saida} (AES-{len(chave) * 8}-GCM)")


if __name__ == "__main__":
    main()
