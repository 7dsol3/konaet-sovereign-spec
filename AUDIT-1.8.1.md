# Revisão de inicialização e verificação da publicação

O X vermelho da edição 1.8.0 correspondia a uma falha real do CI da tag,
embora a execução anterior da mesma revisão em main tivesse passado.
A conferência anterior aceitava uma execução histórica aprovada e não
rejeitava a falha mais recente. Esse critério estava incompleto.

## Problemas reproduzidos e corrigidos

| Problema | Causa confirmada | Correção e regressão |
|---|---|---|
| `EADDRINUSE` no teste mTLS v7 | O fixture escolhia portas com um listener temporário e o fechava antes da geração TLS e do uso real; a porta podia ser ocupada no intervalo | Reserva mantida até a passagem ao listener real, em faixa separada das portas dinâmicas Linux. Teste confere exclusividade e preserva listeners alheios |
| `ENOENT` na implantação concorrente do journal | Depois de `readdir`, outro inicializador podia remover seu próprio `.pending-*` antes do `lstat` | Um temporário reconhecido que desaparece é tolerado. Arquivos estranhos, symlinks, diretórios e erros de permissão continuam recusados; publicação por hard link exclusivo é preservada |
| Resumo de CI indevidamente verde | Um sucesso antigo satisfazia a busca mesmo quando um check posterior falhava | A conferência exige o check mais recente do app esperado; falha, cancelamento, pendência e origem diferente são reprovados |

Falhas originais preservadas:

- [Tag 1.8.0: colisão de porta](https://github.com/7dsol3/konaet-sovereign-spec/actions/runs/41222802704).
- [Tag de fonte medido: corrida de temporário](https://github.com/7dsol3/konaet-sovereign-spec/actions/runs/41223120032).

`tests/startup-stress.mjs` executa 12 rodadas de implantação com dois
processos competidores e 12 rodadas da condição determinística de remoção
do temporário. O CI mantém Windows e Linux ativos mesmo se uma plataforma
falhar, para preservar os dois diagnósticos.

## Escopo da revisão

Foram revistos os caminhos alterados da distribuição: implantação e
recuperação do journal, fixtures de operadores mTLS, SDK de compromissos,
parsers multilíngues, conferência de certificados, allowlist, manifesto,
workflow de build/assinatura, proteção da main e referências do README.
A integração privada da Social teve sua autorização, CSRF, abertura
privada e recuperação conferidos pelos testes existentes.

O contrato, os formatos de transação, a gênese, as cotas e os saldos
existentes não são migrados por esta correção. O formato v1 do journal
continua recuperável; o formato v2 mantém a publicação atômica existente.
O código dos clientes multilíngues e os relatórios medidos da edição 1.8.0
permanecem preservados.

As aprovações valem para os cenários descritos e não demonstram ausência
absoluta de defeitos. Operação permanente sob administrações distintas,
auditoria independente, saturação e perdas físicas de armazenamento
continuam sendo verificações separadas da presente revisão.
