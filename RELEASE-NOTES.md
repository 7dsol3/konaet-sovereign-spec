KONAET 1.9.0 / integração verificável e builds isolados
====================================================

- Ponte MATLAB liga artefatos dos três projetos por SHA-256, revisões Git,
  contexto de execução e eventos causais. O finalizador exige referência de
  confiança independente e recusa vetores válidos de outra execução.
- O harness original finaliza o compromisso em quatro processos, numa cópia
  isolada da revisão commitada, sem alterar os vetores do checkout.
- BTC Lab importado permanece byte a byte. Seu builder operacional usa SDK
  .NET 10.0.404, fontes explícitas e inventário exato. Imports por diretório,
  response files automáticos e fontes NuGet externas ficam desativados.
- Estado local v2 separado do v1; sessões de puzzle não rodam em runners.
- GIF e PNG MATLAB de uma execução real do protocolo acompanham os eventos,
  dados e certificado. A demonstração não é telemetria ao vivo.
- Integração passa a fazer parte dos checks obrigatórios da main. Transporte
  Ubuntu usa somente mirrors sondados; Dependabot e ownership foram ativados.

A evidência arquivada inclui 59 verificações do adaptador, 52 contratos Git e
19 testes do ativador, além da finalização. Os 187 testes do runtime, os nove
clientes polyglot, regressões de build e checkpoint possuem checks separados.
Esses números medem contratos de software, não acurácia universal.

O ZIP continua construído e testado pelo workflow de release, com atestação
Sigstore. O SDK .NET é pré-requisito separado para o worker local. Nenhuma
chave de App, chave de operador ou solução privada de puzzle é distribuída.

As redes, gêneses, saldos e contratos existentes não são migrados. A operação
permanente da rede, avaliação independente e hardware físico continuam
requerendo implantação e ensaios próprios.

Correções preservadas da edição 1.8.1
-----------------------------------

- Corrige uma corrida entre readdir e lstat na implantação concorrente do journal:
  o temporário de outro inicializador pode desaparecer sem causar ENOENT indevido.
- Mantém a exclusividade da implantação e a recusa de entradas não regulares.
- Reserva portas dos fixtures até a inicialização dos operadores mTLS, evitando
  a janela de colisão observada em uma execução Linux da tag 1.8.0.
- A conferência de prontidão exige o resultado mais recente de cada check
  obrigatório; uma aprovação antiga não encobre uma falha posterior.
- CI Windows/Linux inclui 12 rodadas de implantação com dois escritores.
- Kit multilíngue, contratos, gêneses, formatos e saldos mantidos.
- Windows ZIP construído e testado pelo GitHub Actions, com proveniência
  Sigstore assinada pela identidade do workflow e bundle para conferência.
- main protegida por pull request, CI Windows/Linux, bloqueio de force push
  e exclusão, com as regras também aplicadas aos administradores.

As redes e os saldos existentes mantêm suas regras. A homologação remota de
uma hora permanece publicada com seus relatos assinados. Hospedagem da
rede social e dos validadores é uma ativação operacional separada.
