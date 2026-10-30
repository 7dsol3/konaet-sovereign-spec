# Validação e execução da Konaet

O repositório distribui o núcleo VLOCK7SIN, os nós, a política `.ko`, o console
e os testes correspondentes. Os comandos abaixo executam a suíte publicada:

```sh
npm ci --ignore-scripts
npm test
npm run verify
```

## Funcionalidades exercitadas

| Área | Verificação executada | Arquivo |
|---|---|---|
| Eventos assinados | Assinatura, domínio, rede, bytes, checksum e rejeição de adulteração | [event.test.mjs](tests/event.test.mjs) |
| Regras `.ko` | Compilação determinística, saldo, nonce, raiz, contexto e limites de fechamento | [ko.test.mjs](tests/ko.test.mjs) |
| Console e rede | Quatro processos distintos, envio assinado, finalização e convergência de raízes | [console.test.mjs](tests/console.test.mjs) |
| Recuperação | Reinício com novos processos, mesma gênese, raiz, saldos e histórico | [console.test.mjs](tests/console.test.mjs) |
| Acesso local | Recusa de POST sem token da sessão e de origem incompatível | [console.test.mjs](tests/console.test.mjs) |
| Persistência | WAL, corrupção, snapshots, falta de espaço e atomicidade | [runtime.test.js](chain/vlock7sin-js/tests/runtime.test.js) |
| Estado e segurança | Isolamento, serialização canônica, replay e certificados de quórum | [security-regressions.test.js](chain/vlock7sin-js/tests/security-regressions.test.js) |
| Perfis híbridos | Assinaturas, autorização conjunta e quorum híbrido | [hybrid-crypto.test.js](chain/vlock7sin-js/tests/hybrid-crypto.test.js) e [hybrid-quorum.test.js](chain/vlock7sin-js/tests/hybrid-quorum.test.js) |
| Codecs | Entradas geradas, limites uint128, round-trip e adulteração | [property.test.js](chain/vlock7sin-js/tests/property.test.js) |
| Distribuição | Arquivos permitidos, hashes, links e integridade do pacote | [publication.test.mjs](tests/publication.test.mjs) |

## Automação publicada

O workflow [Konaet executable checks](.github/workflows/check.yml) executa
a suíte em **Windows e Linux**. Cada execução registra o commit correspondente
e o resultado de seus jobs na aba
[Actions](https://github.com/7dsol3/konaet-sovereign-spec/actions).

No pacote Windows, `Verificar-Pacote.bat` confere os arquivos distribuídos
com o Node portátil incluído. As chaves da demonstração são geradas somente
na primeira execução do console.

## Executar o serviço online

[Abrir o console nativo](https://konaet-ko-runtime.alkalipixie.chatgpt.site).

O endpoint `/api/runtime` fornece fonte, perfil e hashes do motor. O endpoint
`/api/ko` compila e executa o contexto enviado. O resultado identifica regras
aprovadas, a regra que recusou uma entrada e as regras posteriores ainda não
executadas. [Formato da API e comandos](KO-RUNTIME.md).

## Registros versionados

Os arquivos [source-review.json](evidence/source-review.json) e
[ko-runtime.json](evidence/ko-runtime.json) preservam os registros das edições
anteriores. Os testes atuais são executados diretamente sobre o código
distribuído nesta edição.

As contas e os saldos do aplicativo são próprios da sua rede de demonstração.
O [guia de operação](DEPLOYMENT.md) descreve a configuração de operadores em
máquinas separadas; [Segurança](SECURITY.md) descreve a proteção das chaves.
