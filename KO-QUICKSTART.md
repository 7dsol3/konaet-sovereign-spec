# Comece com .ko

Para funções, storage, mapas, eventos e chamadas Ed25519, use o
**[guia de contratos com estado](KO-PROGRAM.md)** e o
**[.ko Studio](https://7dsol3.github.io/konaet-sovereign-spec/)**.
O guia abaixo descreve o perfil de políticas `ASSERT_V1`.

Use `.ko` para definir regras de aceitação, executá-las com dados de teste e
integrá-las ao perfil nativo da Konaet. Este guia usa o motor distribuído no
repositório e na versão Windows.

[Executar no navegador](https://konaet-ko-runtime.alkalipixie.chatgpt.site/console) ·
[Referência da linguagem e API](KO-RUNTIME.md)

## Pelo navegador

1. Abra o console `.ko`.
2. Edite o fonte ou importe um arquivo `.ko`.
3. Escolha **Transferência** ou **Fechamento** e preencha os dados.
4. Clique em **Compilar e executar**.

O resultado mostra as regras aprovadas ou a primeira regra que rejeitou os
dados. As regras posteriores à rejeição aparecem como não executadas. Os
controles do console permitem baixar o fonte e copiar o hash do programa.

## Criar seu projeto

Com Node.js 24.7+ da série 24, no diretório do repositório:

```sh
npm ci --ignore-scripts
npm run ko -- init minha-politica
```

O comando cria uma pasta nova com:

```text
minha-politica/
  SindraRuntime.ko
  transfer.json
  closure.json
  README.md
```

A criação recusa diretórios existentes e não substitui arquivos do usuário.
Os dois contextos contêm valores de teste, sem contas ou chaves privadas.

## Compilar, executar e conferir

```sh
npm run ko -- compile minha-politica/SindraRuntime.ko
npm run ko -- run minha-politica/SindraRuntime.ko minha-politica/transfer.json
npm run ko -- run minha-politica/SindraRuntime.ko minha-politica/closure.json closure
npm run ko -- online minha-politica/SindraRuntime.ko minha-politica/transfer.json
```

`run` executa pelo motor do pacote. `online` envia o fonte e o contexto à API
pública e confere perfil, fase, quantidade de regras e hashes retornados.
Uma regra rejeitada ou um arquivo inválido encerra o comando com código 1.

Para produzir um artefato compilado e conferir sua integridade:

```sh
npm run ko -- compile minha-politica/SindraRuntime.ko --out politica.compiled.json
npm run ko -- verify politica.compiled.json
```

`verify` recompila o fonte e confere programa, metadados e hashes. A saída de
compilação usa criação exclusiva: um arquivo existente não é sobrescrito.

## Escrever uma regra

No fonte padrão, as regras têm este formato:

```text
rule transferBalance: transfer.amountAtomic <= state.senderBalance
rule transferNonce: transfer.nonce == state.nextNonce
rule closureCount: closure.actCount <= 64
```

Para limitar uma transferência a dez unidades atômicas, altere a regra de
quantidade máxima no seu arquivo:

```text
rule transferMaximum: transfer.amountAtomic <= 10
```

Execute `transfer.json` com quantidade `"7"` para aceitar. Altere para `"11"`
para verificar a recusa. Os valores são **unidades atômicas**: SND possui nove
casas decimais. Dez unidades atômicas correspondem a `0,000000010 SND`.

O perfil atual fixa cabeçalho e identidade SND e permite até 32 regras, fonte
de até 16 KiB e inteiros até uint128. Use LF no arquivo `.ko`, comentários de
linha iniciados por `#` e nomes de regras únicos. As duas fases precisam ter
pelo menos uma regra. A [referência completa](KO-RUNTIME.md) lista os campos.

## Usar em Node.js

```js
const fs = require('node:fs');
const { compileKoPolicy, executeKoPolicy } = require('./chain/vlock7sin-js/src/koPolicy');
const source = fs.readFileSync('runtime/SindraRuntime.ko', 'utf8');
const context = JSON.parse(fs.readFileSync('examples/ko-transfer-context.json', 'utf8'));
const policy = compileKoPolicy(source);
executeKoPolicy(policy, 'transfer', context);
console.log(policy.programSha256);
```

O exemplo pronto é executado por:

```sh
node examples/ko-use.cjs
```

## Chamar a API

O arquivo `examples/ko-request.json` contém fonte, fase e contexto completos.
Com curl:

```sh
curl -H "Content-Type: application/json" --data-binary @examples/ko-request.json https://konaet-ko-runtime.alkalipixie.chatgpt.site/api/ko
```

No PowerShell do Windows, use `curl.exe` para chamar o executável curl.
O serviço retorna HTTP 200 para regras aceitas, 422 para fonte/contexto/regra
rejeitados e 413 para requisições maiores que 32 KiB. O contexto é informado
pelo chamador; os dados enviados a esse serviço são destinados à execução
pública de regras, sem necessidade de chaves privadas.

## Dentro do VLOCK7SIN

No perfil v6, o hash da política pertence à identidade da gênese. O nó obtém
o contexto do evento assinado e do estado verificado do ledger. A política
é aplicada na admissão, no fechamento e na recuperação WAL.

Uma política diferente requer uma gênese e configuração coerentes para a
instância correspondente. O console `.ko` online executa os dados enviados;
o console Windows executa também a sua rede local de demonstração.
Consulte [Operação](DEPLOYMENT.md) para configurar os nós.

## No pacote Windows

Extraia o asset `Konaet-Console-Windows-x64.zip` e abra `Iniciar-Konaet.bat`
para usar a interface. Para os comandos, abra o terminal na pasta extraída
e substitua `npm run ko --` por `bin\node.exe tools\ko.mjs`:

```bat
bin\node.exe tools\ko.mjs init minha-politica
bin\node.exe tools\ko.mjs run minha-politica\SindraRuntime.ko minha-politica\transfer.json
bin\node.exe tools\ko.mjs online minha-politica\SindraRuntime.ko minha-politica\transfer.json
```
