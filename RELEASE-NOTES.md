Konaet Polyglot Receipt Kit e distribuição assinada
==================================================

- Clientes para C, C++, C#, Python, Rust, Perl, Go e Node.js, com entrada Shell,
  para preparar e conferir compromissos destinados ao SocialReceiptRegistry.ko.
- Especificação KRP-0001 em Wikitext e TeX; os documentos não são validadores.
- Vetores comuns, limites de entrada, comparação exata dos dois u128 e
  integração de cada cliente com finalização real em quatro processos.
- Rust com dependências fixadas e C/C++ exercitados com sanitizadores em CI.
- Documentos e salts privados ficam fora da cadeia. A verificação de inclusão,
  execução e finalização continua no verificador Node, com referências fixadas.
- Windows ZIP construído e testado pelo GitHub Actions, com proveniência
  Sigstore assinada pela identidade do workflow e bundle para conferência.
- main protegida por pull request, CI Windows/Linux, bloqueio de force push
  e exclusão, com as regras também aplicadas aos administradores.

As redes e os saldos existentes mantêm suas regras. A homologação remota de
uma hora permanece publicada com seus relatos assinados. Hospedagem da
rede social e dos validadores é uma ativação operacional separada.
