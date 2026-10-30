# Testes e resultados · KNP-003

## Execução da edição 1.2.1

O código dos nós e o console são distribuídos em `chain/`, `console/` e
`tools/`. O teste `tests/console.test.mjs` inicia quatro processos reais,
finaliza transferências assinadas, confere saldo e raízes, recusa gasto sem
saldo e requisições sem autorização, aplica `.ko` e recupera os WALs em novos
processos. Execute `npm ci --ignore-scripts` e `npm test` para repetir.

O CI repete essa execução em Windows e Linux. O resultado é próprio de uma
rede local de demonstração. A API online executa o compilador e o interpretador;
a implantação de validadores em hosts independentes é uma operação separada.

## Histórico das edições anteriores

Revisão de fonte: 30 de outubro de 2026. Os compromissos dos arquivos examinados
estão em [source-review.json](evidence/source-review.json). O checkout de origem
tem modificações locais: o identificador de commit isolado NÃO representa
exatamente todos os bytes examinados. Os hashes por arquivo registram os bytes
revisados; o código integral de origem não acompanha esta edição.

## Matriz de implementação

| Componente | Evidência existente | Estado e limite |
|---|---|---|
| Identidade, evento e codec VLOCK | Fonte e testes locais do runtime; vetor assinado nesta publicação | Implementação local. O vetor é verificável aqui; o nó completo não está incluído. |
| Estado Merkle e execução | Fonte do ledger e testes locais | Não constitui reprodução externa desta publicação. |
| Quórum 3-de-4, troca de líder e sincronização | Registros de testes com WebSocket | Testes locais; nenhuma independência administrativa inferida. |
| WAL e recuperação | Implementações de ledger e journals, cenários locais | Recuperação por operadores externos ainda não comprovada. |
| Perfil híbrido e mTLS | Teste do pacote de operadores e perfis configuráveis | Não significa que todo artefato usa autorização híbrida. |
| Custódia de chaves | Ferramentas de identidade e exportação | Custódia externa e cerimônia operacional pendentes. |
| Fonte `.ko` | Parser declarativo e novo interpretador limitado de assertions | O perfil v6 executa assertions de transferência e fechamento; testes de integração locais e API pública de contexto separado. |
| Money DNA | Avaliação determinística, SHA3-256 e compromisso H5D1 | Observação; estado de ancoragem `ready-not-anchored`. |
| Ativos SQL | Operações e isolamento da aplicação | Autoridade contábil distinta da gênese VLOCK SND. |
| Rede pública | Sem recibo de operação pública fornecido | Não estabelecida pelos resultados locais. |
| Preço e liquidez | Nenhum mercado dos ativos Konaet associado | Não estabelecidos; nenhuma avaliação financeira inferida. |

## Registros anteriores, apresentados pelo mantenedor

O workspace registra 130 suítes e 1.274 testes Jest, 495 testes Node e 13
cenários de navegador aprovados, com SQL isolado nos cenários correspondentes.
São **registros de execução local**, não atestados independentes. Seus resumos
sanitizados constam no recibo de revisão. Os logs completos podem conter dados
de ambiente e não foram copiados para este repositório público.

Os testes de **este repositório** são diferentes: verificam o vetor público,
suas rejeições, os links e a integridade do pacote de documentação. Não se deve
apresentar sua aprovação como nova execução dos 1.274/495/13 testes do sistema.

## O que qualquer pessoa pode verificar aqui

1. Recalcular os hashes dos arquivos publicados.
2. Decodificar o vetor com limites de tamanho e ordem definidos.
3. Conferir o endereço do remetente, a assinatura, o checksum e o identificador.
4. Alterar os dados e executar os casos de rejeição.
5. Ler o estado de cada afirmação e distinguir regras atuais de próximas etapas.

O manifesto de distribuição detecta divergência entre arquivos e hashes, mas
**não substitui assinatura de release, procedência do mantenedor ou auditoria**.
Quem puder substituir os arquivos e o manifesto pode recalcular seus hashes.

A edição 1.1 adiciona [ko-runtime.json](evidence/ko-runtime.json), com o hash do
motor publicado, a identidade do perfil e a separação entre execução da API
pública e integração local no consenso. O serviço público não atesta saldo
nem finalização e não representa operação pública dos validadores.

## O que falta para alegações maiores

- Para operação independente: registros de quatro administrações, suas chaves
  públicas, configurações, observações assinadas e testes prolongados.
- Para operação pública: endpoints, observabilidade, controles de abuso,
  custódia, resposta a incidentes e exercício de restauração.
- Para comparação de redes: mesma carga útil, ponto de medição, critério de
  finalização, hipóteses de falha e reprodução por terceiros.
- Para preços: identidade exata do ativo, mercados executáveis, negociações,
  horário e liquidez. Quantidades em gênese não determinam preço.

A fonte Money DNA usa 8.888.888.888.888 como capacidade simbólica, com
`monetarySupply: false`. A gênese SND usa 1.000.000.000 SND, nove casas decimais.
Essa distinção DEVE permanecer em interfaces, discussões e futuras edições.
