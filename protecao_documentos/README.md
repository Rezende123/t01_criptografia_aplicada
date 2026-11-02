# Proteção de documentos com AES-GCM

Criptografa e descriptografa arquivos com AES-GCM, garantindo duas propriedades:

- **Confidencialidade:** sem a chave, o conteúdo do arquivo não pode ser lido.
- **Integridade e autenticidade:** a tag de autenticação de 16 bytes faz com que
  uma chave incorreta ou qualquer alteração no arquivo seja detectada, e nenhum
  dado é gravado nesses casos.

Requisito: `pip install cryptography`

## Arquivos

| Arquivo | Função |
|---|---|
| `criptografar.py` | Gera o arquivo criptografado a partir do original e da chave |
| `descriptografar.py` | Valida o arquivo criptografado e recupera o original |
| `processo_teste.sh` | Executa os casos de uso de ponta a ponta |
| `hino_bahia.txt` | Documento de exemplo usado nos testes |

## Formato da chave

A chave é uma string hexadecimal de 16, 24 ou 32 bytes (32, 48 ou 64 caracteres),
o que corresponde a AES-128, AES-192 ou AES-256. Os testes usam AES-256, com uma
chave gerada assim:

    openssl rand -hex 32 > chave_aes_256.txt

Ela pode ser informada de duas formas, que não podem ser usadas juntas:

- `-f/--arquivo-chave <arquivo>`: lê o hex de um arquivo de texto em UTF-8 ou UTF-16.
  Espaços e quebras de linha são ignorados. É a forma recomendada, pois evita que a
  chave fique no histórico do terminal.
- `-k/--chave <hex>`: recebe o hex direto na linha de comando.

Guarde a chave com cuidado: sem ela o arquivo não pode ser recuperado.

## Uso

    python criptografar.py hino_bahia.txt -f chave_aes_256.txt -o hino_bahia.txt.enc
    python descriptografar.py hino_bahia.txt.enc -f chave_aes_256.txt -o hino_recuperado.txt

Ou, com a chave na linha de comando:

    python criptografar.py hino_bahia.txt --chave <hex> -o hino_bahia.txt.enc
    python descriptografar.py hino_bahia.txt.enc --chave <hex> -o hino_recuperado.txt

O `-o/--saida` é opcional. Sem ele, a criptografia grava em `<entrada>.enc`, e a
descriptografia remove o `.enc` do nome ou, se ele não existir, acrescenta `.dec`.
Se o arquivo de saída já existir, ele é sobrescrito sem confirmação.

## Como funciona

**Criptografia:**

1. Lê e valida a chave.
2. Gera um nonce aleatório de 12 bytes com `os.urandom`, novo a cada execução.
3. Cifra o arquivo com AES-GCM, usando o cabeçalho como dado associado (AAD).
4. Grava o cabeçalho, o nonce e o texto cifrado com a tag.

**Descriptografia:**

1. Lê e valida a chave.
2. Confere o tamanho mínimo do arquivo, o cabeçalho e a versão.
3. Separa o nonce do texto cifrado e verifica a tag.
4. Grava o arquivo de saída somente se a verificação passar.

## Formato do arquivo criptografado

| Bytes | Conteúdo |
|---|---|
| 4 | cabeçalho `AGCM` |
| 1 | versão (1) |
| 12 | nonce aleatório (novo a cada criptografia) |
| N + 16 | texto cifrado + tag de autenticação GCM |

São 33 bytes a mais que o original: `hino_bahia.txt` tem 107 bytes e
`hino_bahia.txt.enc` tem 140.

O cabeçalho entra como dado associado (AAD) e também é autenticado.

## Casos de uso testados

O script `processo_teste.sh` instala a dependência, gera a chave e executa os casos
abaixo:

    bash processo_teste.sh

| Etapa | Caso de uso | Resultado esperado | Mensagem do teste |
|---|---|---|---|
| 2 | Criptografar `hino_bahia.txt` com a chave gerada | `hino_bahia.txt.enc` é criado | — |
| 3 | Descriptografar com a chave correta | `hino_recuperado.txt` é idêntico ao original (`cmp`) | `OK: arquivo recuperado e identico ao original.` |
| 4 | Descriptografar com outra chave, também válida | `InvalidTag`; nenhum arquivo é gerado | `OK: descriptografia recusada como esperado.` |
| 5 | Descriptografar um arquivo com 1 bit invertido | `InvalidTag`; nenhum arquivo é gerado | `OK: adulteracao detectada como esperado.` |

Na etapa 5, o bit invertido está no byte 20 do arquivo. Como o cabeçalho e o nonce
ocupam os bytes 0 a 16, esse byte pertence ao texto cifrado.

Cada execução do script gera uma nova `chave_aes_256.txt` e sobrescreve os arquivos
anteriores. Um `.enc` criado com a chave antiga deixa de poder ser descriptografado,
portanto não use esses nomes para guardar documentos reais.

## Tratamento de erros

Em todos os casos abaixo, o script mostra a mensagem de erro, sai com código 1 e não
grava nenhum arquivo.

| Situação | Comportamento |
|---|---|
| Chave incorreta ou arquivo adulterado | `InvalidTag`: "falha na autenticação" |
| Chave fora do formato hexadecimal ou com tamanho inválido | Erro de validação da chave |
| Arquivo de chave ou de entrada inexistente | Erro de leitura |
| Arquivo pequeno demais ou sem o cabeçalho `AGCM` | "não está no formato esperado" |
| Versão de formato diferente de 1 | "versão de formato não suportada" |

O GCM não distingue chave incorreta de arquivo adulterado: nos dois casos a tag não
confere, por isso a mensagem de erro é a mesma.

## Limitações

- O arquivo é carregado inteiro na memória, então a solução não é adequada para
  arquivos muito grandes.
- A chave é gerada e guardada manualmente: não há derivação a partir de senha nem
  gerenciamento de chaves.
- Quem tem a chave pode tanto ler quanto gerar arquivos válidos. A tag não identifica
  o autor e, portanto, não substitui uma assinatura digital.
