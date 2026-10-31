Recibos da Konaet Social e distribuição assinada
================================================

- Novo SocialReceiptRegistry.ko: compromissos de eventos autorizados, com salt,
  sem conteúdo privado na chamada e com capacidade explícita por instância.
- SDK Node para preparar compromissos e verificar inclusão, execução e
  finalização com gênese e contrato fixados.
- Integração testada em quatro processos, incluindo autorização, adulteração,
  preservação de saldos e recuperação do registro após reinício.
- Windows ZIP construído e testado pelo GitHub Actions, com proveniência
  Sigstore assinada pela identidade do workflow e bundle para conferência.
- main protegida por pull request, CI Windows/Linux, bloqueio de force push
  e exclusão, com as regras também aplicadas aos administradores.

As redes e os saldos existentes mantêm suas regras. A homologação remota de
uma hora permanece publicada com seus relatos assinados. Hospedagem da
rede social e dos validadores é uma ativação operacional separada.
