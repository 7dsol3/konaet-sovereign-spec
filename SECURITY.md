# Segurança

## Console 1.3.0

O console abre HTTP e quatro listeners WebSocket em `127.0.0.1`, com portas
automáticas. As requisições que assinam transferências exigem um token aleatório
da sessão e conferem a origem. Não há exposição automática à rede externa.

As seis identidades de teste são geradas com aleatoriedade criptográfica na
primeira execução. Seeds, gênese, WAL e histórico ficam em `.konaet-demo/`,
diretório ignorado pelo Git e excluído dos pacotes. Não compartilhe esse
diretório nem utilize nele chaves ou saldos de produção. As permissões Unix
solicitadas são restritas; no Windows a proteção efetiva depende das ACLs do
diretório do usuário. O console de demonstração não implementa cofre de chaves.

Quatro processos no mesmo computador compartilham a mesma administração.
O runner de operador incluído atende instalação separada, mTLS e identidades
individuais. Consulte [DEPLOYMENT.md](DEPLOYMENT.md) para operação entre máquinas.

## Verificador e runtime

O verificador público confere o perfil de evento descrito em PROTOCOL.md.
O interpretador `.ko` limita fonte, regras e contexto, sem avaliação de código
arbitrário. No nó, a política complementa as regras obrigatórias do ledger.

O manifesto confere consistência dos arquivos. A chave de confiança de uma
distribuição deve ser obtida por canal independente quando isso for exigido
pelo operador.

## Relatar problemas

Abra uma issue com versão, entradas de teste, passos e resultado esperado.
Para vulnerabilidades sensíveis, utilize os advisories privados do repositório
quando disponíveis. Não publique seeds, credenciais ou dados reais.

Artefatos suportados nesta edição: nós, runtime, console e documentação 1.3.0.
