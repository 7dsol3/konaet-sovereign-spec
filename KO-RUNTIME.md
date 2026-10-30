# Runtime .ko · KNP-004

O perfil `KONAET_KO_ASSERT_V1` compila uma linguagem limitada de
assertions para um programa determinístico. O interpretador executa comparações
inteiras e igualdade de hashes. Não usa `eval`, não executa JavaScript enviado
pelo usuário, não possui funções, loops, I/O, custódia ou emissão monetária.

## Executar online

Interface: **https://konaet-ko-runtime.alkalipixie.chatgpt.site/console**.

Para criar um projeto e executar os exemplos, veja [Comece com .ko](KO-QUICKSTART.md).

- `GET /api/runtime`: perfil, fonte padrão e hashes.
- `POST /api/ko`: recebe `source`, `phase` e `context` em JSON.
- `phase`: `transfer` ou `closure`.
- Quantidades no contexto: strings inteiras canônicas, sem ponto flutuante.
- Resposta 200: assertions aceitas para o contexto fornecido.
- Resposta 422: regra, fonte ou contexto rejeitados; 413: corpo excedente.

**O contexto é fornecido pelo chamador. A API não consulta uma conta real,
verifica assinatura ou finaliza transferência.** A integração no nó, descrita
adiante, obtém contexto diretamente do evento e do estado local verificado.

## Fonte e limites

### Linha de comando

```sh
npm run ko -- compile runtime/SindraRuntime.ko
npm run ko -- run runtime/SindraRuntime.ko examples/ko-transfer-context.json
npm run ko -- online runtime/SindraRuntime.ko examples/ko-transfer-context.json
npm run ko -- init minha-politica
npm run ko -- compile runtime/SindraRuntime.ko --out politica.compiled.json
npm run ko -- verify politica.compiled.json
```

`compile` produz o programa e seus hashes. `run` executa o contexto no motor
do pacote. `online` envia fonte e contexto ao serviço público e confere se o
programa executado corresponde ao hash compilado na sua máquina. O resultado
identifica perfil, fase, regras e modo de execução. Uma recusa encerra o
comando com código 1.

No pacote Windows, o equivalente usa o Node incluído:

```bat
bin\node.exe tools\ko.mjs online runtime\SindraRuntime.ko examples\ko-transfer-context.json
```

O último argumento opcional seleciona `transfer` ou `closure`. O arquivo
de exemplo contém dados de teste do contexto de transferência.

### Formato da política

[SindraRuntime.ko](runtime/SindraRuntime.ko) é a política padrão. Há no máximo
16 KiB de fonte ASCII com LF e 32 regras. O cabeçalho e a identidade SND são
fixos neste perfil. Cada regra tem a forma:

```text
rule transferBalance: transfer.amountAtomic <= state.senderBalance
rule closureCount: closure.actCount <= 64
```

Os operadores são `==`, `<=`, `>=`, `<`, `>`. Hashes permitem apenas igualdade
entre campos de hash. Os nomes de campos e fases são uma lista fechada;
operações desconhecidas, duplicatas, quantidades não canônicas e tipos
incompatíveis são recusados.

| Fase | Campos disponíveis | Tipo |
|---|---|---|
| Transferência | `transfer.amountAtomic`, `transfer.nonce`, `transfer.networkId` | Inteiros exatos |
| Estado da transferência | `state.senderBalance`, `state.nextNonce`, `state.networkId` | Inteiros exatos |
| Raízes da transferência | `transfer.previousRoot`, `state.root` | Hash hexadecimal canônico de 32 bytes |
| Fechamento | `closure.actCount`, `closure.byteLength` | Inteiros exatos |

O lado esquerdo da regra é um campo `transfer.*` ou `closure.*`; o lado
direito pode ser um campo compatível ou uma constante inteira. Operandos
das duas fases não são misturados. No JSON, os inteiros usam strings
decimais canônicas, como `"7"` e `"100"`.

O compilador produz fonte, AST, perfil, SHA-256 da fonte e SHA-256 do programa.
O descritor recebido de outra parte é recompilado e comparado. Não basta
anexar um hash válido a um programa diferente.

## Integração no consenso

O perfil `konaet-sovereign-genesis-v6-ko-policy`, protocolo
`0.5.0-sovereign-ko.1`, incorpora o descritor completo da política. Os hashes
entram no compromisso de parâmetros e a gênese identifica a instância.
Remover ou trocar a política muda a rede e suas raízes; não é uma atualização
silenciosa de uma rede já existente.

No runtime integrado, as regras são executadas:

1. Na admissão individual e em lote, antes da inserção no grafo.
2. Na preparação e confirmação dos fechamentos.
3. Na recuperação pelo WAL e na validação do perfil dos snapshots.

O código de estado, assinatura, autorização híbrida e quórum continua exigido.
A política `.ko` restringe a aceitação; não substitui essas verificações.
Versões anteriores da gênese preservam seus compromissos e formatos.

## Código integrado e execução

O compilador do nó está em
[chain/vlock7sin-js/src/koPolicy.js](chain/vlock7sin-js/src/koPolicy.js).
O [ledger](chain/vlock7sin-js/src/ledger.js) aplica a política durante a
admissão, o fechamento e a recuperação. O
[nó VLOCK7SIN](chain/network/sovereign/SovereignNode.js) recebe a política
definida pela gênese v6.

O aplicativo Windows executa esses módulos em quatro processos validadores.
O teste [console.test.mjs](tests/console.test.mjs) inicia os processos, envia
transferências assinadas, confere raízes e saldos e reinicia a rede pelos WALs.
Veja [Validação e execução](EVIDENCE.md) para os comandos de teste.
