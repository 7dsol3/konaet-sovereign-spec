# Um validador Konaet como serviço Linux

O template mantém um operador VLOCK em execução, reinicia o processo quando
ele falha e envia SIGTERM no desligamento. Ele serve para uma máquina Linux
com systemd 250+ e Node.js 24.7+ da série 24 instalado em `/usr/bin/node`.
O arquivo é um template de operação; a publicação dele não provisiona uma
máquina nem comprova que uma rede esteja online.

Cada operador mantém sua própria instalação, chave, certificado e WAL. Para
o perfil inicial de quatro validadores, use quatro máquinas sob os controles
administrativos acordados. O número da instância deve coincidir com o ID:
`konaet-validator@0` usa `validator-0` e `/var/lib/konaet/validator-0`.
Este procedimento é executado pelo administrador do host escolhido.

## Diretórios e identidade

Instale uma cópia conferida da distribuição em `/opt/konaet`, com os arquivos
de código pertencendo a root e somente leitura para o usuário do serviço.
Execute `npm ci --ignore-scripts` durante a preparação da distribuição. A
máquina precisa da dependência `ws` incluída no repositório, acesso privado
aos outros três peers e relógio sincronizado.

Crie uma conta de sistema exclusiva para o serviço e um diretório separado
dos fontes. Os comandos abaixo são exemplos para o operador 0, em uma
instalação nova:

```sh
sudo useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin konaet-validator
sudo install -d -o root -g konaet-validator -m 0750 /var/lib/konaet/validator-0
sudo install -d -o konaet-validator -g konaet-validator -m 0700 /var/lib/konaet/validator-0/data
```

Gere a identidade localmente usando `chain/scripts/createOperatorIdentity.js`.
A pasta de destino deve existir. Esse gerador também produz material híbrido
para perfis anteriores; v7 usa a seed Ed25519 e a configuração v7 deve omitir
`consensusIdentityFile`. Envie aos demais operadores somente os dados públicos.
A seed, a chave TLS e o token de submissão permanecem no host do operador.

Use `chain/scripts/buildIndependentGenesis.js` para gerar a gênese a partir
do roster público acordado, com `contractRuntime` igual a `PROFILE` em
`chain/vlock7sin-js/src/koConsensusProfile.js` e a política nativa `.ko`.
Confiram o mesmo `genesisSha256` e `genesisId` entre os quatro operadores.
Guarde `operator-config.json`, gênese e material TLS dentro da pasta do
operador. Todos os caminhos do JSON são relativos a essa pasta, sem links
simbólicos, com `dataDirectory` igual a `data`.

O JSON usa `scope: "private-testnet-no-value"`, `mutualTlsRequired: true`,
`validatorId`, `host`, `port`, `statusPort`, `genesisFile`, `genesisSha256`,
`seedFile`, `caFile`, `certificateFile`, `tlsKeyFile`, `submitTokenFile` e
`peers`. Cada peer tem `validatorId` e URL `wss://IP_PRIVADO:PORTA/`.
Use portas distintas a partir de 1024. A interface e todos os peers precisam
ser IPv4 loopback ou RFC1918; uma VPN deve atribuir endereços compatíveis.
Os certificados precisam de CN correspondente ao ID e SAN com o IP usado,
emitidos pela CA da malha e dentro do prazo de validade.

Defina os arquivos de configuração e os segredos como root:konaet-validator,
com modo 0640, e mantenha a pasta sem permissão de escrita para o serviço.
O template permite escrita somente em `data/`. Não coloque configurações,
seeds, tokens, certificados privados ou backups no GitHub ou em `/opt/konaet`.
Não reutilize as identidades de teste do console.

## Conferir e ativar no host

Depois de preparar os arquivos, valide a configuração e a unit no Linux:

```sh
sudo -u konaet-validator /usr/bin/node /opt/konaet/chain/scripts/runIndependentValidator.js check /var/lib/konaet/validator-0/operator-config.json
sudo install -o root -g root -m 0644 /opt/konaet/deploy/validator/konaet-validator@.service /etc/systemd/system/konaet-validator@.service
sudo systemd-analyze verify /etc/systemd/system/konaet-validator@.service
sudo systemctl daemon-reload
sudo systemctl enable --now konaet-validator@0.service
sudo systemctl status konaet-validator@0.service
sudo journalctl -u konaet-validator@0.service --since '10 minutes ago'
```

Não ative uma segunda cópia com a mesma identidade e o mesmo WAL. O serviço
mantém a porta HTTP de status/submissão em `127.0.0.1`; a porta WSS escuta na
interface privada configurada. A unit não altera firewall, DNS ou roteador.
Uma entrada pública HTTPS precisa de um gateway separado e configurado para
encaminhar eventos já assinados. O token de operador não deve chegar ao
navegador. A referência do serviço não instala esse gateway.

## Observar finalização e recuperar falhas

Consulte `http://127.0.0.1:STATUS_PORT/status` localmente e compare `genesisId`,
`sequence` e `root` nos quatro hosts. A raiz do ledger também aparece nas
consultas `/account/ENDERECO_V7` como `root`. Monitore peers,
erros, espaço livre, reinícios do processo e vencimento dos certificados.
HTTP 200 em `/status` indica que a consulta respondeu; não demonstra quórum.
Use também `/health/ready`: HTTP 503 sinaliza quórum local indisponível,
certificado perto do vencimento, encerramento ou chamadas pendentes paradas.
HTTP 200 nesse endpoint resume a observação local e deve ser confirmado com
as raízes e certificados; conexões aparentes não provam finalização.
HTTP 202 em `/submit` indica admissão. A finalização é confirmada pelo
certificado de quórum e pela raiz reproduzida.

O perfil inicial exige três assinaturas em quatro validadores. Pare ou
atualize somente um validador por vez e aguarde sua sincronização antes de
prosseguir. Se dois estiverem indisponíveis, a rede poderá parar de finalizar.
Reinícios rápidos repetidos atingem o limite de cinco tentativas em cinco
minutos; investigue os logs e a configuração antes de executar
`systemctl reset-failed konaet-validator@0.service`.

A edição 1.7 recupera locks reconhecidos de processos comprovadamente mortos
somente após validar o WAL, preservando os tokens em arquivos `.abandoned-*`.
Locks vivos, tokens desconhecidos e dados corrompidos continuam bloqueando
o início. Siga o [procedimento de recuperação](../../RECOVERY.md); não
transforme o reinício do serviço em uma rotina de apagar locks.

O procedimento de backup mais simples usa parada controlada de um único
operador, cópia consistente de sua gênese/configuração e de todo `data/`, e
reinício antes de fazer o mesmo no próximo operador. Proteja separadamente
as chaves com cópia criptografada e acesso restrito. Preserve WAL, snapshot,
estado de replay, nonces e votos persistidos juntos. Uma cópia de chaves sem
esses estados não é um ponto de recuperação completo. Não remova locks nem
edite arquivos para contornar uma recusa de recuperação.

Teste a restauração com a cópia original desligada. Um estado antigo pode
conter nonces e votos já usados: restauração exige verificar a estratégia
de identidade e de sincronização antes de voltar a assinar. Não execute
uma identidade clonada simultaneamente. Compare a posição e raiz com os
peers e confirme uma nova finalização após recuperar o nó.

Programe renovação de certificados antes do vencimento e reaplique apenas
o material daquele operador. Valide com `check`, reinicie um nó por vez e
confirme a malha. Não distribua a chave privada da CA junto com os certificados.

O template foi preparado no Windows e precisa de `systemd-analyze verify`
e de um ensaio de inicialização, parada, falha e recuperação no Linux alvo.
Nenhum servidor Linux foi instalado ou iniciado por esta publicação.

Referências: [configuração de serviços systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[isolamento e permissões](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
