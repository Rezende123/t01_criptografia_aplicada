# Proteção de documentos com AES-GCM

Requisito: `pip install cryptography`

## Formato da chave
Hexadecimal de 16, 24 ou 32 bytes (32, 48 ou 64 caracteres), ou seja AES-128, AES-192 ou AES-256.
A chave pode ser passada direto (`-k/--chave <hex>`) ou lida de um arquivo de texto
com o hex dentro (`-f/--arquivo-chave <arquivo>`); espaços e quebras de linha são ignorados.
Ler de arquivo evita que a chave fique no histórico do terminal. As duas opções não podem ser usadas juntas.
Guarde a chave com cuidado: sem ela o arquivo não pode ser recuperado.

## Uso

    python criptografar.py hino_bahia.txt -f chave.txt -o hino_bahia.txt.enc
    python descriptografar.py hino_bahia.txt.enc -f chave.txt -o hino_recuperado.txt

Ou, com a chave na linha de comando:

    python criptografar.py hino_bahia.txt --chave <hex> -o hino_bahia.txt.enc
    python descriptografar.py hino_bahia.txt.enc --chave <hex> -o hino_recuperado.txt

## Formato do arquivo criptografado

| Bytes | Conteúdo |
|---|---|
| 4 | cabeçalho `AGCM` |
| 1 | versão (1) |
| 12 | nonce aleatório (novo a cada criptografia) |
| N + 16 | texto cifrado + tag de autenticação GCM |

O cabeçalho entra como dado associado (AAD) e também é autenticado.

## Chave errada
Com chave incorreta ou arquivo adulterado, o GCM lança `InvalidTag`; o script
mostra uma mensagem clara, sai com código 1 e não grava nenhum arquivo.
