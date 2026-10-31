# Segurança

## Console 1.8.0

O console abre HTTP e quatro listeners WebSocket em `127.0.0.1`, com portas
automáticas. As requisições que assinam transferências exigem um token aleatório
da sessão e conferem a origem. Não há exposição automática à rede externa.

As seis identidades de teste são geradas com aleatoriedade criptográfica na
primeira execução. Seeds, gênese, WAL e histórico ficam em `.konaet-console-v7/`,
diretório ignorado pelo Git e excluído dos pacotes. Não compartilhe esse
diretório nem utilize nele chaves ou saldos de produção. As permissões Unix
solicitadas são restritas; no Windows a proteção efetiva depende das ACLs do
diretório do usuário. O console de demonstração não implementa cofre de chaves.

Quatro processos no mesmo computador compartilham a mesma administração.
O runner de operador incluído atende instalação separada, mTLS e identidades
individuais. Consulte [DEPLOYMENT.md](DEPLOYMENT.md) para operação entre máquinas.

## Operadores e gateway

Os peers mTLS são supervisionados com desafios ping/pong. Uma conexão
sem resposta é terminada para permitir reconexão. A prontidão é uma
observação local de conectividade, pendências e validade dos certificados;
ela não comprova administração independente ou finalização de um pedido.

O gateway inicia apenas em loopback e em modo de leitura. Ele verifica
eventos assinados antes de encaminhá-los, mantém o token do operador no
servidor e filtra os dados de status. Para expor submissões, o administrador
precisa configurar HTTPS, autenticação de clientes e limites na entrada.
Assinatura válida identifica um remetente; ela não concede capacidade
ilimitada de armazenamento. Consulte [GATEWAY.md](GATEWAY.md).

A edição 1.6.0 corrige o reaproveitamento de um registro de contrato já
validado no cache de outra rede pela API em memória. O mesmo identificador
de rede passa a ser verificado também no caminho do cache.

## Verificador e runtime

O verificador de certificados aceita `--genesis-id` e `--previous-root`
para comparar os hashes esperados da rede e do estado anterior. Obtenha
essas referências por um canal confiável independente. A saída explicita
se cada referência foi fixada; um recibo autocontido de outra rede pode
ser criptograficamente consistente sem pertencer à rede desejada.

O verificador público confere o perfil de evento descrito em PROTOCOL.md.
O interpretador `.ko` limita fonte, regras e contexto, sem avaliação de código
arbitrário. No nó, a política complementa as regras obrigatórias do ledger.

O manifesto confere consistência dos arquivos. A chave de confiança de uma
distribuição deve ser obtida por canal independente quando isso for exigido
pelo operador.

## Relatar problemas

## Distribuição assinada e proteção do repositório

A `main` exige pull request e os checks `verify (ubuntu-latest)` e
`verify (windows-latest)` do GitHub Actions, inclusive para administradores.
Force push e exclusão estão bloqueados. Não é exigida uma aprovação humana
independente quando não há outro revisor designado.

O workflow `signed-release.yml` exige uma tag na mesma revisão da `main`
que executa a publicação, confere a versão, testa os fontes e o ZIP extraído
e gera proveniência Sigstore com identidade OIDC. O bundle é publicado junto
ao ZIP. A assinatura atesta a origem do build; não representa auditoria
independente, exclusividade do código ou aprovação de segurança absoluta.
Releases existentes não são sobrescritas por esse workflow.

## Relatar problemas

Abra uma issue com versão, entradas de teste, passos e resultado esperado.
Para vulnerabilidades sensíveis, utilize os advisories privados do repositório
quando disponíveis. Não publique seeds, credenciais ou dados reais.

Artefatos suportados nesta edição: nós, runtime, console, gateway e documentação 1.8.0.
