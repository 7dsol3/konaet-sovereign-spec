# Capacidade e recuperação — edição 1.7

## Permissões de implantação na gênese v8

O perfil `AUTHORIZED_PROFILE`, exportado por
[`koConsensusProfile.js`](chain/vlock7sin-js/src/koConsensusProfile.js), usa
a gênese `konaet-sovereign-genesis-v8-ko-admission` e o protocolo
`0.7.0-sovereign-ko-admission.1`.

Um roster novo de operadores deve incluir esse objeto em `contractRuntime`
e uma `deploymentPolicy` com a estrutura abaixo. Substitua os endereços
pelos endereços públicos reais dos participantes autorizados:

```json
{
  "schema": "konaet.contract-deployment-policy.v1",
  "deployers": [
    { "address": "v7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "maxContracts": 64 },
    { "address": "v7bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "maxContracts": 64 }
  ]
}
```

Cada endereço é único, cada cota é positiva e a soma das cotas não pode
ultrapassar 128. Uma identidade não autorizada não pode implantar contratos,
mesmo se tiver SND. Uma identidade autorizada só ocupa sua própria cota;
não ocupa a reserva de outra. Essas regras são executadas pelos validadores,
incluídas na gênese, nos snapshots, nas provas de conta e na raiz do estado.

O construtor de gênese
[`buildIndependentGenesis.js`](chain/scripts/buildIndependentGenesis.js)
transmite essa política ao validador de gênese. O operador deve conferir
o roster e fixar o `genesisId` antes de iniciar a rede.

Esse é um perfil de implantação autorizada. Não implementa uma economia
permissionless de taxas ou stake. O orçamento de gas mede execução e não
é uma tarifa monetária. Chamadas a contratos existentes continuam sujeitas
às assinaturas, ao nonce e às regras escritas no próprio contrato.

Novos diretórios do console recebem uma gênese v8 com cotas para Alice e
Bob. O diretório `.konaet-console-v7/` mantém seu nome por compatibilidade;
a versão efetiva é a da gênese armazenada. Uma pasta já existente recupera
sua própria rede v7 ou v8. A atualização não reescreve gênese, saldos,
chaves, WALs ou regras de uma rede anterior. Para adotar v8 em uma rede
antiga, prepare uma rede separada e um plano explícito de migração.

## Reinício após queda do processo

Os nós mantêm locks exclusivos de escritor para ledger, votos e mudanças
de rodada. Na inicialização, um lock abandonado só é recuperado se:

1. O arquivo é regular, limitado e contém um token reconhecido.
2. O sistema operacional confirma que o PID proprietário não existe.
3. O WAL correspondente é regular e passa na conferência de integridade
   e decodificação; seus bytes e o lock não mudam durante a conferência.
4. Nenhuma outra tentativa de recuperação possui o marcador exclusivo.

O token é preservado em `.lock.abandoned-IDENTIFICADOR`. Não é apagado.
Depois disso, o nó abre os journals, verifica os registros e reproduz o
estado antes de começar a operar. A recuperação não trunca WALs, altera
votos ou redefine nonces.

PID vivo, PID reutilizado, permissão insuficiente para examinar o PID,
token desconhecido, arquivo ausente/corrompido ou marcador `.lock.recovery`
impedem a recuperação automática. Esses estados exigem investigação do
operador. Não apague locks ou copie uma identidade ativa para outra máquina
para forçar o início.

Para recuperar um host:

1. Preserve uma cópia consistente do diretório e examine o erro e os logs.
2. Confirme que não há outra instância da mesma identidade assinando.
3. Tente a inicialização normal. Um WAL íntegro de um processo morto é
   recuperado automaticamente, com os tokens antigos preservados.
4. Se houver corrupção ou recuperação incompleta, mantenha o serviço
   parado e use um backup consistente de gênese, WALs, votos, replay e
   nonces sob um procedimento de restauração validado. Não restaure apenas
   o saldo nem uma cópia antiga dos votos enquanto outra instância assina.
5. Compare gênese, sequência e raiz com os peers e confirme um novo
   certificado de quórum após a sincronização.

O teste de regressão mata um processo validador, recupera os três journals,
confere a mesma raiz e finaliza uma nova chamada `.ko`. Ele também verifica
que locks de proprietários vivos e WALs corrompidos são preservados.

## Histórico e sincronização

O nó monta um índice de sequência/offset na recuperação e o atualiza após
cada fechamento persistido. Consultas de sincronização leem somente os
frames selecionados, conferindo tamanho e checksum. Cada resposta é limitada
pelo número de registros da gênese e por um orçamento de 4 MiB de leitura.
O índice é reconstruído do WAL; não é uma fonte independente de confiança.

Eventos vencidos saem do cache do nó, e rodadas de sequências concluídas
são liberadas. O WAL e o histórico do ledger continuam preservados. Esta
edição não implementa poda do histórico completo ou checkpoints automáticos
para reduzir o armazenamento de uma rede de duração ilimitada. Dimensione
disco/memória e valide carga prolongada antes de operação pública contínua.

## Journal standalone e encerramento do console

Novas implantações standalone publicam programa, opções e estado inicial
em um único registro atômico exclusivo, `deployment.json`. Uma falha antes
da publicação pode ser repetida no diretório vazio ou com temporários não
publicados. Uma implantação já publicada nunca é substituída. O leitor
mantém compatibilidade com o formato anterior de dois arquivos.

O console limita o tempo de leitura do corpo e o número de conexões. Ao
encerrar, espera uma tolerância curta, fecha conexões restantes e para os
processos validadores. Chamadas repetidas de fechamento compartilham a mesma
operação. Uma conexão incompleta não mantém os validadores abertos sem um
prazo próprio de desligamento.

## Reprodução

Com Node 24.22.2 ou posterior da série 24:

```sh
npm ci --ignore-scripts
node --test tests/recovery-and-capacity.test.cjs
npm test
npm run verify
```

O Studio continua executando a VM na sessão do navegador. Publicação de
código e testes locais não instala automaticamente servidores ou uma rede
de validadores públicos permanentes.
