# Runtime .ko · KNP-004

Edição 1.1.0. O perfil `KONAET_KO_ASSERT_V1` compila uma linguagem limitada de
assertions para um programa determinístico. O interpretador executa comparações
inteiras e igualdade de hashes. Não usa `eval`, não executa JavaScript enviado
pelo usuário, não possui funções, loops, I/O, custódia ou emissão monetária.

## Executar online

Interface: **https://konaet-ko-runtime.alkalipixie.chatgpt.site**.

- `GET /api/runtime`: perfil, fonte padrão e hashes.
- `POST /api/ko`: recebe `source`, `phase` e `context` em JSON.
- `phase`: `transfer` ou `closure`.
- Quantidades no contexto: strings inteiras canônicas, sem ponto flutuante.
- Resposta 200: assertions aceitas para o contexto fornecido.
- Resposta 422: regra, fonte ou contexto rejeitados; 413: corpo excedente.

**O contexto é fornecido pelo chamador. A API não consulta uma conta real,
verifica assinatura ou finaliza transferência.** A integração no nó, descrita
adiante, obtém contexto diretamente do evento e do estado local verificado.

## Fonte e limites

[SindraRuntime.ko](runtime/SindraRuntime.ko) é a política padrão. Há no máximo
16 KiB de fonte ASCII com LF e 32 regras. O cabeçalho e a identidade SND são
fixos neste perfil. Cada regra tem a forma:

```text
rule transferBalance: transfer.amountAtomic <= state.senderBalance
rule closureCount: closure.actCount <= 64
```

Os operadores são `==`, `<=`, `>=`, `<`, `>`. Hashes permitem apenas igualdade
entre campos de hash. Os nomes de campos e fases são uma lista fechada;
operações desconhecidas, duplicatas, quantidades não canônicas e tipos
incompatíveis são recusados.

O compilador produz fonte, AST, perfil, SHA-256 da fonte e SHA-256 do programa.
O descritor recebido de outra parte é recompilado e comparado. Não basta
anexar um hash válido a um programa diferente.

## Integração no consenso

O perfil `konaet-sovereign-genesis-v6-ko-policy`, protocolo
`0.5.0-sovereign-ko.1`, incorpora o descritor completo da política. Os hashes
entram no compromisso de parâmetros e a gênese identifica a instância.
Remover ou trocar a política muda a rede e suas raízes; não é uma atualização
silenciosa de uma rede já existente.

No runtime integrado, as regras são executadas:

1. Na admissão individual e em lote, antes da inserção no grafo.
2. Na preparação e confirmação dos fechamentos.
3. Na recuperação pelo WAL e na validação do perfil dos snapshots.

O código de estado, assinatura, autorização híbrida e quórum continua exigido.
A política `.ko` restringe a aceitação; não substitui essas verificações.
Versões anteriores da gênese preservam seus compromissos e formatos.

## Evidência

O workspace executou oito testes novos, incluindo alteração de política,
rejeição de transferência assinada, atomicidade de lote, snapshot, WAL e
convergência de quatro nós WebSocket com sincronização de nó atrasado. São
testes locais, não operação independente em quatro máquinas.

O código público desta pasta é o mesmo compilador/interpretador usado nessa
integração. O nó completo não está incluído. Os testes públicos verificam o
motor e seus limites; o recibo diferencia esses testes da integração local.
