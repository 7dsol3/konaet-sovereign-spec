<div align="center">
  <img src="assets/konaet-native-cover.svg" width="100%" alt="Konaet Soberana — tecnologia com identidade própria">

  <p><a href="https://konaet-ko-runtime.alkalipixie.chatgpt.site">Ecossistema Konaet</a> · <a href="https://konaet-ko-runtime.alkalipixie.chatgpt.site/console">Console .ko online</a> · <a href="KO-QUICKSTART.md">Comece com .ko</a> · <a href="https://wa.me/message/43CXZJ7NW2FPDO">Projetos e parcerias</a></p>
</div>

# Konaet Soberana

**Native Chain · Console 1.3.0 · Runtime .ko**

Nós VLOCK7SIN, transações assinadas, consenso por quórum, sincronização,
persistência WAL e regras nativas `.ko`. Esta edição publica o código dos nós
e um console que inicia quatro processos validadores no seu computador.

[Console online](https://konaet-ko-runtime.alkalipixie.chatgpt.site/console) ·
[Baixar para Windows](https://github.com/7dsol3/konaet-sovereign-spec/releases/latest/download/Konaet-Console-Windows-x64.zip) ·
[Releases](https://github.com/7dsol3/konaet-sovereign-spec/releases)

![Mapa de alto nível: regras .ko, validação, VLOCK7SIN e estado; Money DNA e ativos com identidades próprias.](assets/konaet-architecture.svg)

## Identidade do ecossistema

| Ativo | Papel |
|---|---|
| <img src="assets/snd.svg" width="26" height="26" alt=""> **SINDRA · SND** | Unidade da gênese VLOCK7SIN, com política .ko e nove casas decimais |
| <img src="assets/naet.svg" width="26" height="26" alt=""> **NAET** | Unidade do ledger da aplicação Konaet |
| <img src="assets/kwrk.svg" width="26" height="26" alt=""> **Konaet Work · KWRK** | Unidade de trabalho do ecossistema |
| <img src="assets/kact.svg" width="26" height="26" alt=""> **Konaet Actum · KACT** | Unidade ligada à execução contabilizada pela aplicação |

**Money DNA:** `8.888.888.888.888` unidades simbólicas de referência da
política, com significado distinto de saldo financeiro ou cotação.
[Conheça as identidades e os fluxos](ECOSYSTEM.md).

## Seu primeiro projeto .ko

```sh
npm ci --ignore-scripts
npm run ko -- init minha-politica
npm run ko -- run minha-politica/SindraRuntime.ko minha-politica/transfer.json
npm run ko -- online minha-politica/SindraRuntime.ko minha-politica/transfer.json
```

O projeto inclui fonte, contexto de transferência e contexto de fechamento.
[Guia com exemplos, artefatos compilados e integração](KO-QUICKSTART.md).

## Usar no Windows

1. Baixe **Konaet-Console-Windows-x64.zip** nos assets da release 1.3.0.
2. Clique com o botão direito → **Extrair tudo**.
3. Abra a pasta extraída e dê dois cliques em **Iniciar-Konaet.bat**.

O navegador abre o console. Envie SND de teste entre Alice e Bob, acompanhe
os quatro processos, os fechamentos, a raiz e o histórico. O console também
compila e executa `.ko`. Use **Encerrar console** para parar os validadores.
Ao abrir novamente, a rede recupera os dados do WAL.

O ZIP inclui Node.js: não precisa instalar Node, npm ou configurar um roster.
As chaves de demonstração são geradas na primeira execução, dentro de
`.konaet-demo/`. Os saldos de demonstração não têm valor monetário e são
separados dos saldos da sua carteira Konaet.

O download automático **Source code (zip)** do GitHub é o código-fonte.
O aplicativo pronto para Windows é o asset **Konaet-Console-Windows-x64.zip**.

## Executar pelo código — Windows, Linux e macOS

Com Node.js 24.7 ou superior da série 24:

```sh
git clone https://github.com/7dsol3/konaet-sovereign-spec.git
cd konaet-sovereign-spec
npm ci --ignore-scripts
npm start
```

A única dependência é a cópia de runtime da biblioteca WebSocket `ws`, incluída
em `vendor/ws` com licença MIT. `npm ci` instala essa cópia local.
Para usar sem abrir o navegador automaticamente:

```sh
node tools/console.mjs --no-browser
```

## O que roda

| Componente | Código | Comportamento |
|---|---|---|
| Nó VLOCK7SIN | [SovereignNode.js](chain/network/sovereign/SovereignNode.js) | Recebe eventos, troca votos, finaliza por quórum e sincroniza peers |
| Ledger | [ledger.js](chain/vlock7sin-js/src/ledger.js) | Confere assinatura, saldo, nonce, estado e política `.ko` |
| Runtime `.ko` | [koPolicy.js](chain/vlock7sin-js/src/koPolicy.js) | Compila e executa nove regras padrão com inteiros exatos |
| Gênese v6 | [SovereignGenesis.js](chain/network/sovereign/SovereignGenesis.js) | Vincula fonte e programa `.ko` à identidade da rede |
| Persistência | [persistence.js](chain/vlock7sin-js/src/persistence.js) | WAL, snapshots e recuperação do estado |
| Console | [console.mjs](tools/console.mjs) | Interface HTTP local, transferências assinadas e quatro processos |
| Operador | [runIndependentValidator.js](chain/scripts/runIndependentValidator.js) | Identidade individual, mTLS e configuração de malha privada |

O console online executa políticas sobre o contexto informado. O console
Windows executa também os nós e as transferências da sua própria rede local.
Operadores em outras máquinas usam o [guia de operação](DEPLOYMENT.md).

## Testar o funcionamento

```sh
npm test
npm run verify
```

O teste de integração inicia quatro processos distintos, envia transações
assinadas, verifica convergência, rejeita gasto sem saldo, encerra os processos
e recupera os mesmos saldos e raiz depois de reiniciar. Também testa o bloqueio
de requisições sem autorização local e a aplicação de `.ko`.
O CI executa os testes em Windows e Linux.

## Executar `.ko` pela linha de comando

```sh
npm run ko -- compile runtime/SindraRuntime.ko
npm run ko -- run runtime/SindraRuntime.ko examples/ko-transfer-context.json
npm run ko -- online runtime/SindraRuntime.ko examples/ko-transfer-context.json
```

O comando `online` executa na API pública e confere o hash do programa
retornado. [Formato, contexto e comandos](KO-RUNTIME.md).

## Documentação

- [Operação e separação entre demonstração e rede pública](DEPLOYMENT.md)
- [Comece com .ko](KO-QUICKSTART.md)
- [Ecossistema, ativos e Money DNA](ECOSYSTEM.md)
- [Runtime .ko e formato da política](KO-RUNTIME.md)
- [Nomenclatura Konaet](NOMENCLATURE.md)
- [Perfil de evento assinado](PROTOCOL.md)
- [Testes, resultados e escopo](EVIDENCE.md)
- [Segurança](SECURITY.md) e [licença ISC](LICENSE)

O manifesto de distribuição confere a integridade dos arquivos publicados.
Consulte a [arquitetura e os recursos da Konaet](COMPARISON.md) para acompanhar
o caminho do fonte `.ko` até a execução pelos validadores.

Projeto de [7dsol3](https://github.com/7dsol3). As edições anteriores permanecem
nas tags. O [puzzle do dia](assets/puzzle-do-dia.png) continua como material de
humor do projeto.
