Correções de inicialização e verificação da publicação
=====================================================

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
