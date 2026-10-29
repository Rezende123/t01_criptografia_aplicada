#!/usr/bin/env bash
# Teste de criptografia/descriptografia com AES-256-GCM.
# Uso: bash teste.sh   (a partir de qualquer pasta)

cd "$(dirname "$0")" || exit 1

echo "=================================================="
echo " ETAPA 0: Instalando dependencia (cryptography)"
echo "=================================================="
pip install cryptography

echo
echo "=================================================="
echo " ETAPA 1: Gerando chave AES-256 (32 bytes em hex)"
echo "=================================================="
openssl rand -hex 32 > chave_aes_256.txt
echo "Chave salva em chave_aes_256.txt"

echo
echo "=================================================="
echo " ETAPA 2: Criptografando hino_bahia.txt"
echo "=================================================="
python criptografar.py hino_bahia.txt --arquivo-chave chave_aes_256.txt -o hino_bahia.txt.enc

echo
echo "=================================================="
echo " ETAPA 3: Descriptografando com a chave correta"
echo "=================================================="
python descriptografar.py hino_bahia.txt.enc -f chave_aes_256.txt -o hino_recuperado.txt
if cmp -s hino_bahia.txt hino_recuperado.txt; then
    echo "OK: arquivo recuperado e identico ao original."
else
    echo "FALHA: arquivo recuperado difere do original."
fi

echo
echo "=================================================="
echo " ETAPA 4: Descriptografando com chave INCORRETA"
echo " (esperado: falha com InvalidTag)"
echo "=================================================="
openssl rand -hex 32 > chave_aes_256_incorreto.txt
python descriptografar.py hino_bahia.txt.enc -f chave_aes_256_incorreto.txt -o hino_recuperado_incorreto.txt \
    && echo "FALHA: descriptografou com chave errada!" \
    || echo "OK: descriptografia recusada como esperado."

echo
echo "=================================================="
echo " ETAPA 5: Descriptografando arquivo ADULTERADO"
echo " (esperado: falha com InvalidTag)"
echo "=================================================="
# Copia o arquivo cifrado e inverte um bit de um byte do texto cifrado.
python -c "
import sys
dados = bytearray(open('hino_bahia.txt.enc', 'rb').read())
dados[20] ^= 0x01
open('hino_bahia_incorreto.txt.enc', 'wb').write(dados)
"
echo "Arquivo adulterado gerado: hino_bahia_incorreto.txt.enc"
python descriptografar.py hino_bahia_incorreto.txt.enc -f chave_aes_256.txt -o hino_recuperado_adulterado.txt \
    && echo "FALHA: descriptografou arquivo adulterado!" \
    || echo "OK: adulteracao detectada como esperado."

echo
echo "=================================================="
echo " FIM DOS TESTES"
echo "=================================================="
