# Homologação operacional concluída — 31/10/2026

**Quatro VMs reais operaram durante uma hora, com mTLS, transações assinadas,
contratos `.ko`, perda/retorno de quórum e recuperação de um validador após SIGKILL.**

[Execução completa no GitHub](https://github.com/7dsol3/konaet-sovereign-spec/actions/runs/41210381147)
· [Resumo verificável](evidence/remote-hour-2026-10-31/verified-summary.json)
· [Roteiro e reprodução](REMOTE-VALIDATION.md).

![Disponibilidade dos validadores, avanço dos fechamentos e memória observada na execução de uma hora.](assets/remote-endurance.svg)

## Resultados conferidos

| Critério | Resultado |
|---|---|
| Duração após convergência inicial | 3.603.784 ms — 60 minutos e 3,784 segundos |
| Infraestrutura | Quatro VMs Ubuntu distintas; quatro identidades e instâncias de sistema operacional |
| Transferências | 415 |
| Chamadas `.ko` com estado | 138, além da implantação inicial |
| Fechamentos | 554 |
| Estado do contrato Counter | 276, conforme 138 chamadas com incremento de 2 |
| Oferta nativa SND | Preservada; soma dos saldos finais conferida |
| Raízes finais | Mesma raiz nos quatro validadores |
| Certificado final | Conferido com três assinantes |
| Perda de quórum | Dois validadores parados; nenhuma finalização sem quórum |
| Retorno do quórum | Transação pendente retomada sem nova submissão |
| Queda forçada | SIGKILL em um validador; três nós continuaram e o reiniciado recuperou/sincronizou o estado |
| Encerramento | Quatro processos encerrados de forma controlada ao final |

Raiz final:

```text
bb9cd59b44be0d9b606279186cb519dc8208fcd102763694d13516b3195afea7
```

O controlador reexecutou as transições e conferiu os certificados. Um quinto
job independente dos processos validadores conferiu os quatro relatos finais,
as assinaturas, a duração e o certificado. A conferência foi repetida fora
do GitHub, incluindo oferta e valor final do contrato. Os arquivos públicos
permitem repetir essa verificação sem as chaves privadas das VMs.

## Tempos e carga

| Medida | Valor |
|---|---|
| p50 | 988 ms |
| p95 | 1.095 ms |
| p99 | 1.184 ms |
| Amostras temporizadas | 553 |

Os tempos medem submissão até convergência dos nós ativos, com transporte
e polling do controlador. A implantação inicial é temporizada; a submissão
pendente do cenário de perda de quórum é verificada separadamente. O gerador
respeita o limite original de dez admissões por minuto. O ensaio valida
funcionamento e recuperação nessa carga; não mede saturação ou capacidade
máxima da rede, nem constitui comparação equivalente com outra blockchain.

O gráfico usa as [amostras externas](evidence/remote-hour-2026-10-31/external-observations.jsonl)
e os estados/intervalos dos relatos assinados. O RSS representa o pico
observado até cada amostra, não uma medição contínua de toda alocação.

## Fonte executada e rastreabilidade

O commit executado foi `8cdf7e01767e3b9e4df92323e4fd7ca1d350ef91`.
Os 66 arquivos do runtime em `chain/`, excluindo apenas o número de versão
em `chain/package.json`, foram comparados por SHA-256 e permaneceram
idênticos na preparação desta publicação.
[Rastreabilidade e cinco jobs aprovados](evidence/remote-hour-2026-10-31/provenance.json).

- [Relato do validador 0](evidence/remote-hour-2026-10-31/result-0.json).
- [Relato do validador 1](evidence/remote-hour-2026-10-31/result-1.json).
- [Relato do validador 2](evidence/remote-hour-2026-10-31/result-2.json).
- [Relato do validador 3](evidence/remote-hour-2026-10-31/result-3.json).
- [Relato do controlador, gênese, certificado e estados](evidence/remote-hour-2026-10-31/controller.json).

Os registros incluem somente chaves públicas, certificados públicos,
transições, estados e medições. Seeds, chaves TLS privadas, chave da CA e
tokens de submissão não foram exportados.

## Serviço Linux e proxy HTTPS

[Validação em Ubuntu 24.04 com systemd e Nginx](https://github.com/7dsol3/konaet-sovereign-spec/actions/runs/41211952165).

O serviço foi instalado com usuário restrito e isolamento, passou em
`systemd-analyze verify`, recuperou um SIGKILL automaticamente e passou
em parada/reinício controlados. O gateway separado e o Nginx passaram
em TLS com certificado conferido, autenticação de submissões, bloqueio
de escrita, rotas privadas e filtragem do status.

Essa integração identificou e corrigiu duplicação do cabeçalho `nosniff`
no proxy. A preparação do ensaio também identificou e corrigiu a retomada
de trabalho pendente após reconexão de quórum.

[Resultado do serviço](evidence/linux-service-2026-10-31.json)
· [Resultado HTTPS/gateway](evidence/linux-gateway-2026-10-31.json).
O teste do serviço isolado preservou a raiz inicial de sequência zero;
recuperação após transações foi exercitada na rede de quatro VMs.

## Conferir localmente

```sh
npm ci --ignore-scripts
npm test
npm run verify
```

`npm run verify` verifica a publicação e os relatos arquivados. O comando
distingue a assinatura de um vetor sintético do certificado e estado da
execução remota. O [verificador de relatos](tools/remote/verify-report.mjs)
recusa assinatura/contexto incorretos, hosts repetidos, duração insuficiente,
divergência de raiz, oferta incorreta ou valor incompatível do contrato.

## Escopo operacional

As quatro VMs pertencem à mesma conta e provedor. O resultado demonstra
instâncias de sistema operacional distintas e execução entre máquinas;
não atesta quatro administrações independentes. Os hosts e relays eram
temporários e foram encerrados ao final. Hospedagem permanente requer uma
instalação própria e sua supervisão.

Foram usadas gênese, contas e chaves exclusivas da homologação, sem importar
saldos da instalação existente. Os resultados confirmam os critérios
executados; revisão formal, pentest externo, saturação e falhas físicas de
armazenamento são verificações distintas.
