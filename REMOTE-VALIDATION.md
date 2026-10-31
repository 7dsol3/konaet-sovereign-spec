# Homologação operacional entre máquinas

O workflow **Konaet remote endurance** executa quatro validadores em quatro
VMs Ubuntu separadas do GitHub Actions. Cada VM gera sua própria chave
Ed25519 e chave TLS. São máquinas sob a mesma conta e provedor; a execução
não demonstra quatro administrações independentes.

## Transporte e proteção das chaves

Cada VM abre um endpoint temporário que transporta bytes TCP por WebSocket.
O mTLS da Konaet permanece dentro desse canal, de ponta a ponta entre os
validadores. Os relays e o intermediário não recebem as chaves TLS nem
decifram esse canal interno. Os proxies locais permitem executar o runner
original com seus endpoints privados e verificação de identidade habilitada.

Os artefatos intermediários contêm somente chaves públicas, CSRs,
certificados públicos, endpoints, gênese e informações de execução.
Seeds, chaves privadas TLS, chave da CA e tokens de submissão permanecem nos
diretórios privados de cada VM. O processo do relay não recebe o token de
acesso à API do GitHub.

As operações de falha exigem comandos assinados por uma identidade de
controle exclusiva da execução, com domínio, identificador, prazo e número
monotônico. O endpoint público não oferece shell nem assinatura de transações.
Somente a porta do transporte autenticado é encaminhada ao validador; seu
RPC de submissão continua em loopback.

As contas e a gênese pertencem exclusivamente à homologação. A execução
não importa saldos ou identidades de uma instalação existente.

## Critérios de aceitação

1. Quatro identidades de validador e quatro identificadores de instância
   de sistema operacional distintos.
2. Mesma gênese e raiz nos quatro hosts, com assinaturas dos relatórios
   conferidas contra as chaves acordadas.
3. Transferências e chamadas `.ko` contínuas pelo período solicitado.
4. Reexecução das transições, integridade do WAL e certificados de quórum
   conferidos por um observador separado do processo validador.
5. Ausência de finalização com dois validadores disponíveis.
6. Retomada de uma transação pendente após a volta do quórum, sem depender
   de uma nova submissão.
7. Encerramento forçado de um validador, continuação com quórum e recuperação
   de seus journals e estado ao reiniciar.
8. Oferta preservada, total do contrato coerente, raiz final convergente e
   encerramento dos processos pertencentes à execução.

O verificador final recusa relatórios com duração insuficiente, assinatura
inválida, hosts repetidos, falhas de cenário ou raiz divergente. Um job que
falha não é apresentado como validação concluída.

## Execução e resultados

Use a aba Actions e o workflow **Konaet remote endurance**. A execução manual
aceita de 180 a 7.200 segundos após a convergência inicial; o valor padrão
manual é 3.600 segundos. O relatório identifica o commit e a duração exatos.
O desenvolvimento na branch de validação começa com um smoke de conectividade
antes do ensaio prolongado.

O workflow usa runners padrão de repositório público e relays temporários.
O gerador respeita o limite original de dez submissões por minuto do operador;
esse controle não é desabilitado para a homologação.
Os processos e endpoints são encerrados ao concluir ou cancelar o job.
Os artefatos públicos intermediários têm retenção curta. O resumo final
informa duração, operações, falhas aplicadas, memória observada e tempos de
convergência p50/p95/p99, incluindo transporte e polling do controlador.
Esses tempos não são uma comparação equivalente com outras redes.

Os relays temporários atendem à execução de duração definida. Hospedagem
permanente, distribuição entre provedores, administração por operadores
distintos, restauração de backups e revisão externa exigem critérios e
infraestrutura próprios.

Referências de infraestrutura: [runners do GitHub](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
e [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).
