# Comparar exige o mesmo problema

Uma documentação pode ser mais específica ao projeto sem que sua rede seja
mais rápida ou mais segura. A [nomenclatura de interoperabilidade Ethereum](https://github.com/ethereum/L2-interop/blob/main/NOMENCLATURE.md)
organiza termos de comunicação entre redes. Esta publicação define vocabulário
Konaet, separa autoridade e evidência e inclui um verificador de evento. Esses
escopos diferentes não estabelecem um ranking entre protocolos.

## Critérios para uma comparação publicável

| Dimensão | Método mínimo | Estado desta publicação |
|---|---|---|
| Vazão | Eventos válidos finalizados por segundo, mesma carga, duração e contagem de rejeições | Comparação entre redes não executada. |
| Latência | Do envio autenticado à finalização verificável; p50, p95 e p99 | Não há medição equivalente BTC/ETH/Konaet aqui. |
| Segurança | Modelo de adversário, hipóteses de honestidade, limites de quórum e revisão do protocolo | Nenhuma superioridade geral comprovada. |
| Independência | Administrações, chaves e infraestrutura sob controle distinto | Os registros referidos são locais. |
| Recuperação | Falhas de energia, disco, rede, restauração e sincronização com verificação de estado | Há cenários locais; falta operação externa prolongada. |
| Custo | Hardware, rede, armazenamento e energia medidos para a mesma função | Nenhum custo comparável publicado aqui. |
| Privacidade | Dados expostos por transações, logs, RPC e observabilidade | Perfil de ameaça e auditoria precisam acompanhar o lançamento público. |
| Economia | Preço negociado, liquidez, oferta circulante e condições de execução | Não estabelecidos para os ativos Konaet. |

Hashes por segundo, respostas HTTP de leitura e eventos finalizados são medidas
diferentes. O tempo de confirmar uma operação de aplicação SQL não deve ser
comparado diretamente com a finalização de uma rede independente.

## Modelo de afirmação

Uma afirmação de desempenho deve identificar:

```json
{
  "claim": "resultado especifico",
  "workload": "eventos e tamanho dos dados",
  "completionCriterion": "ponto verificavel de conclusao",
  "environment": "hardware e topologia",
  "sourceDigest": "codigo executado",
  "rawSamples": "amostras publicadas",
  "failures": "falhas e exclusoes",
  "independentReproduction": false
}
```

O exemplo acima é um modelo de documentação, não um resultado medido.
Uma frase como “mais rápida” só deve aparecer acompanhada do resultado e do
escopo em que a diferença foi demonstrada.

O meme do README expressa humor sobre a complexidade das discussões técnicas.
Não é evidência de desempenho, fraude ou inferioridade de outro projeto.
