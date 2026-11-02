# Proteção e Integridade de Documentos

## 1. Contexto e objetivo

A empresa fictícia XYZW Tecnologia precisa enviar documentos comerciais por canais que não são necessariamente confiáveis, como e-mail ou armazenamento compartilhado. O destinatário deve conseguir ler cada documento exatamente como foi enviado, e um terceiro com acesso ao arquivo em trânsito não deve conseguir lê-lo nem alterá-lo sem que isso seja percebido.
 
Consideramos um adversário capaz de ler, copiar, modificar, truncar e substituir o arquivo criptografado, mas que não conhece a chave. Essa é a situação de um ataque ativo, e por isso apenas cifrar o conteúdo não é suficiente: também é preciso detectar alterações.

Para atender a esses requisitos, implementamos a criptografia e a descriptografia de arquivos com AES-GCM, usando a biblioteca `cryptography` do Python.

## 2. Fundamentação técnica

### 2.1 Criptografia simétrica

Na criptografia simétrica, a mesma chave é usada para cifrar e decifrar, e por isso as duas pontas precisam compartilhá-la previamente. Esse modelo é eficiente, mas deixa um problema a resolver: como entregar a chave ao destinatário com segurança (seção 6).

### 2.2 AES

O AES (*Advanced Encryption Standard*, FIPS 197) é uma cifra de bloco que opera sobre blocos de 128 bits. Ele aceita chaves de 128, 192 ou 256 bits, com 10, 12 ou 14 rodadas, respectivamente.

Adotamos o AES-256 nos testes. A chave tem 32 bytes (256 bits), representados por 64 caracteres hexadecimais, já que cada caractere codifica 4 bits. Uma busca exaustiva exigiria da ordem de 2^256 tentativas, o que é inviável na prática.

Como a cifra de bloco processa apenas um bloco por vez, é preciso um **modo de operação** para cifrar arquivos de tamanho arbitrário.

### 2.3 Modo GCM

O GCM (*Galois/Counter Mode*, NIST SP 800-38D) é um modo de **criptografia autenticada com dados associados** (AEAD). Ele combina duas construções:

- **Modo contador (CTR), para a confidencialidade:** o AES cifra valores de contador, gerando uma sequência pseudoaleatória (*keystream*) que é combinada com o texto claro por XOR. Isso transforma o AES em uma cifra de fluxo, de modo que o texto cifrado tem o mesmo tamanho do texto claro.
- **GHASH, para a autenticação:** uma função de hash universal, calculada por multiplicações no corpo finito GF(2^128). Ela resume os dados associados e o texto cifrado.

Com nonce de 96 bits, como no nosso caso, o processo é o seguinte, em que `K` é a chave, `N` o nonce, `A` os dados associados, `P` o texto claro e `C` o texto cifrado:

```text
H    = AES_K(0^128)                  (subchave de autenticação)
J0   = N || 0^31 || 1                (bloco inicial do contador)
C_i  = P_i XOR AES_K(J0 + i)         (i = 1, 2, ...)
T    = AES_K(J0) XOR GHASH_H(A, C)   (tag de 128 bits)
```

Na descriptografia, a tag é recalculada e comparada com a recebida **antes** de qualquer texto claro ser devolvido. Se forem diferentes, a operação falha, e a biblioteca lança a exceção `InvalidTag`.

### 2.4 Por que a autenticação é necessária

O modo CTR sozinho é **maleável**: inverter um bit do texto cifrado inverte o mesmo bit do texto claro, sem afetar o restante. Verificamos isso decifrando um arquivo alterado apenas com CTR, sem checar a tag. Ao inverter um bit do quarto byte do texto cifrado, o início do documento mudou de `Hino do` para `Hinn do`, e nenhum erro foi indicado.

Em um documento comercial, esse tipo de alteração poderia mudar um valor ou uma data sem que ninguém percebesse. A tag do GCM impede isso: o adversário não conhece `H` nem `AES_K(J0)` e, portanto, não consegue calcular uma tag válida para o conteúdo alterado. Como a tag tem 128 bits, a chance de uma falsificação ser aceita é desprezível, da ordem de 2^-128 multiplicada pelo tamanho da mensagem em blocos.

### 2.5 O papel do nonce

O nonce (*number used once*) não é secreto, mas **nunca pode se repetir com a mesma chave**. Se isso acontecer, as duas mensagens usam o mesmo *keystream*, e surgem dois problemas:

- **Perda de confidencialidade:** o XOR dos dois textos cifrados é igual ao XOR dos dois textos claros, o que confirmamos em um teste com o nonce repetido de propósito.
- **Perda de autenticidade:** o adversário pode obter informações sobre `H` e passar a forjar tags (ataque descrito por Joux, 2006).

Por isso, o programa gera um nonce novo de 12 bytes (96 bits) com `os.urandom` a cada criptografia. Com nonces aleatórios, o NIST limita o uso de uma mesma chave a 2^32 mensagens, mantendo a probabilidade de colisão abaixo de 2^-32. Esse limite é folgado para o cenário da empresa.

### 2.6 Dados associados (AAD)

Os dados associados são autenticados, mas não cifrados. Na nossa solução, o cabeçalho de 5 bytes (identificador `AGCM` e versão) é passado como AAD, o que vincula a versão do formato ao conteúdo. O nonce não entra como AAD, mas também fica protegido: alterá-lo muda `J0` e, consequentemente, a tag esperada.

## 3. Implementação

| Item | Decisão |
|---|---|
| Algoritmo | AES-256-GCM, pela classe `AESGCM` da biblioteca `cryptography` |
| Ambiente | Python 3.12.3 e `cryptography` 50.0.2 |
| Geração da chave | `openssl rand -hex 32` |
| Armazenamento da chave | Arquivo de texto, fora do controle de versão (`.gitignore`) |
| Geração do nonce | `os.urandom(12)`, a cada criptografia |

A biblioteca foi usada em vez de uma implementação própria do algoritmo porque código criptográfico caseiro está sujeito a erros sutis, como comparações de tag vulneráveis a ataques de temporização.

O arquivo criptografado tem a seguinte estrutura:

| Bytes | Conteúdo | Protegido por |
|---|---|---|
| 0 a 3 | Identificador `AGCM` | AAD |
| 4 | Versão do formato (1) | AAD |
| 5 a 16 | Nonce | Entra no cálculo de `J0` |
| 17 a N+16 | Texto cifrado (N bytes) | CTR e tag |
| Últimos 16 | Tag de autenticação | — |

Isso acrescenta 33 bytes por arquivo. No nosso teste, o original tem 107 bytes e o criptografado, 140.

## 4. Experimentos e resultados

Os casos principais são reproduzidos pelo script `processo_teste.sh`. Os testes complementares (seção 4.3) foram feitos à parte, com um script auxiliar que não faz parte da entrega, sobre uma cópia dos programas.

O documento usado foi `hino_bahia.txt`.

> **Pendência:** o enunciado pede um documento comercial fictício, e este arquivo ainda não atende a esse requisito. Ao substituí-lo, é preciso repetir os testes e atualizar os nomes e tamanhos citados neste relatório.

### 4.1 Criptografia e descriptografia com a chave correta

```bash
python criptografar.py hino_bahia.txt --arquivo-chave chave_aes_256.txt -o hino_bahia.txt.enc
python descriptografar.py hino_bahia.txt.enc -f chave_aes_256.txt -o hino_recuperado.txt
```

O arquivo recuperado é idêntico ao original, o que foi confirmado com o comando `cmp` e pela comparação dos hashes SHA-256.

### 4.2 Chave incorreta e conteúdo alterado

| Teste | Alteração | Resultado | Arquivo gerado? |
|---|---|---|---|
| Chave incorreta | Outra chave válida de 256 bits | `InvalidTag` | Não |
| Texto cifrado alterado | 1 bit invertido no byte 20 | `InvalidTag` | Não |

Nos dois casos, o programa terminou com código de saída 1 e exibiu a mensagem abaixo:

```text
Erro: falha na autenticação (InvalidTag). A chave está incorreta ou o arquivo foi corrompido/adulterado. Nenhum arquivo foi gerado.
```

O GCM não distingue as duas causas, pois em ambas a tag calculada não confere. Com a chave incorreta, `H` e `AES_K(J0)` mudam. Com o conteúdo alterado, muda a entrada do GHASH. Esse é o comportamento desejado, pois o adversário não recebe nenhum texto claro parcial nem indicação de qual parte falhou.

### 4.3 Testes complementares

| Teste | Resultado | Código de saída |
|---|---|---|
| 1 bit invertido no nonce | `InvalidTag` | 1 |
| 1 bit invertido na tag | `InvalidTag` | 1 |
| Último byte removido | `InvalidTag` | 1 |
| 1 bit invertido no identificador | Rejeitado pela checagem de formato | 1 |
| 1 bit invertido na versão | Rejeitado pela checagem de versão | 1 |
| Arquivo com menos de 33 bytes | Rejeitado pela checagem de formato | 1 |
| Mesmo documento criptografado duas vezes | Nonces e arquivos diferentes; ambos decifram | 0 |
| Um `.enc` válido no lugar de outro, com a mesma chave | **Aceito**, sem erro | 0 |

Em nenhum dos casos rejeitados foi criado um arquivo de saída.

Dois resultados merecem comentário:

- **Cabeçalho:** o identificador e a versão alterados são recusados pelas checagens do programa antes de chegar ao GCM, portanto o AAD não é exercitado nesses testes. Para verificá-lo, deciframos diretamente pela biblioteca com um AAD diferente do original, e o resultado foi `InvalidTag`.
- **Substituição:** o último teste mostra um limite real da solução. Uma tag válida prova que o arquivo foi gerado com a chave e não foi alterado, mas não prova que é o documento esperado nem o mais recente (seção 5.2).

## 5. Propriedades de segurança

### 5.1 Propriedades garantidas

Supondo que a chave permaneça secreta e que o nonce não se repita:

| Propriedade | Como é garantida | Evidência |
|---|---|---|
| **Confidencialidade** | Cifragem em modo CTR com AES-256 | Sem a chave correta, nenhum texto claro é obtido; cifrar duas vezes gera resultados diferentes |
| **Integridade** | Tag GCM sobre o texto cifrado e o AAD | Qualquer bit alterado no nonce, no texto cifrado ou na tag causa rejeição; o cabeçalho é recusado pelas checagens e, no teste direto, por `InvalidTag` |
| **Autenticidade da origem** (limitada) | Só quem tem a chave consegue gerar uma tag válida | Arquivos alterados sem a chave são recusados |

Formalmente, a combinação de confidencialidade contra ataques de texto claro escolhido com integridade do texto cifrado implica segurança contra ataques de texto cifrado escolhido (Bellare e Namprempre, 2000). A análise de segurança do GCM foi apresentada por McGrew e Viega (2004).

A autenticidade é limitada porque a chave é compartilhada: a tag prova que o arquivo veio de **algum** detentor da chave, mas não de qual deles.

### 5.2 Propriedades não garantidas

- **Não repúdio:** o remetente pode negar a autoria, pois o destinatário também poderia ter gerado o arquivo. Isso exigiria assinatura digital.
- **Proteção contra repetição ou substituição:** como testado na seção 4.3, um `.enc` antigo ou de outro documento é aceito se usar a mesma chave. Isso poderia ser mitigado incluindo no AAD o identificador do documento e sua versão ou data, verificados pelo destinatário.
- **Disponibilidade:** o adversário pode apagar ou corromper o arquivo. A solução detecta a corrupção, mas não recupera o conteúdo.
- **Sigilo de metadados:** o nome do arquivo e o tamanho exato do documento não são ocultados.
- **Sigilo futuro** (*forward secrecy*): se a chave vazar, todos os arquivos cifrados com ela poderão ser lidos, inclusive os antigos.

## 7. Conclusão

A solução cifrou o documento com AES-256-GCM, e a descriptografia com a chave correta recuperou um arquivo idêntico ao original. Os testes com chave incorreta e com conteúdo alterado foram rejeitados com `InvalidTag`, sem gerar arquivo de saída.

Assim, confidencialidade e integridade ficam garantidas, além de uma autenticidade limitada aos detentores da chave. Essas garantias dependem de manter a chave em segredo e de não repetir o nonce. A solução não oferece não repúdio nem proteção contra substituição por outro arquivo válido, e a distribuição segura da chave continua sendo um problema a resolver fora dela.

## Referências

- BELLARE, M.; NAMPREMPRE, C. *Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm*. ASIACRYPT, 2000.
- JOUX, A. *Authentication Failures in NIST version of GCM*. Comentário enviado ao NIST, 2006.
- McGREW, D.; VIEGA, J. *The Security and Performance of the Galois/Counter Mode of Operation*. INDOCRYPT, 2004.
- NIST. *FIPS 197: Advanced Encryption Standard (AES)*. 2001, atualizado em 2023.
- NIST. *SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*. 2007.
- PYCA. *cryptography: documentação de Authenticated Encryption*. Disponível em: https://cryptography.io/en/latest/hazmat/primitives/aead/.
- STALLINGS, W. *Criptografia e Segurança de Redes: Princípios e Práticas*. Pearson.
