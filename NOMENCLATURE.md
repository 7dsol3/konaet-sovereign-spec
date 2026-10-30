# Nomenclatura Konaet · KNP-001

Edição 1.0.0 · 30 de outubro de 2026

Esta especificação dá nomes distintos a identidade, autoridade, dados e
evidência. Os termos descrevem o projeto; não concedem autoridade a um
componente nem declaram uma implantação concluída. **DEVE**, **NÃO DEVE** e
**PODE** expressam requisitos desta documentação. O cumprimento depende de
implementação e verificação, descritas em [EVIDENCE.md](EVIDENCE.md).

## Identidade e domínio

| Termo | Definição e critério observável |
|---|---|
| Konaet Soberana | Identidade do projeto e de suas regras próprias. O nome sozinho não constitui evidência de segurança ou operação pública. |
| Protocolo soberano | Regras pelas quais os validadores concordam sobre eventos e estado. Sua versão DEVE ser identificada no perfil da rede. |
| Rede | Instalações que compartilham uma gênese e as regras de validação. Compartilhar um nome ou símbolo não é suficiente. |
| Identidade de rede | Identificador acompanhado do hash da gênese e da versão do protocolo. O identificador numérico isolado não demonstra equivalência entre redes. |
| Gênese | Configuração inicial que fixa validadores, alocações, parâmetros e compromissos iniciais de uma instância. |
| Perfil de protocolo | Conjunto explícito de formato, algoritmos, domínios e regras de aceitação. Perfis diferentes NÃO DEVEM ser aceitos como equivalentes por conveniência. |
| Instância local | Rede executada numa máquina, ainda que haja vários processos e chaves. |
| Instância independente | Instalação com administração e custódia distintas, comprovadas além do processo ou IP. |
| Entrada pública | Serviço acessível por usuários externos para consultas ou envio de eventos. Não implica validação aberta a qualquer participante. |
| Validação permissionada | Participação no consenso limitada ao conjunto autorizado pela gênese ou regra de atualização. |
| Validação aberta | Entrada no conjunto de consenso por regras públicas implementadas. Não é o perfil comprovado da rede atual. |

## Evento, estado e finalização

| Termo | Definição e critério observável |
|---|---|
| Evento / ato | Unidade assinada com codificação canônica, rede, remetente, destino, quantidade e dados de ordenação. |
| Bytes canônicos | Representação única admitida por um perfil. Bytes adicionais, campos inválidos e formas alternativas NÃO DEVEM ser normalizados silenciosamente. |
| Identificador de evento | Compromisso calculado sobre o registro canônico com separação de domínio. Não é, sozinho, prova de inclusão. |
| Nonce | Contador da conta usado pelas regras de execução para impedir repetição. Sua validade exige consultar o estado. |
| Sequência | Posição lógica declarada pelo evento ou fechamento. Deve ser interpretada no contexto do protocolo. |
| Nexus | Referência causal canônica presente num evento. Não significa ponte ou vínculo monetário com outra rede. |
| Estado | Dados contábeis e de protocolo usados para verificar uma transição. |
| Raiz de estado | Compromisso criptográfico do estado sob regras definidas. Uma raiz sem contexto não comprova o seu significado. |
| Transição | Aplicação determinística de eventos elegíveis sobre um estado anterior. |
| Fechamento | Unidade de avanço de estado certificada pelo protocolo VLOCK. Não deve ser confundida automaticamente com um bloco SQL da aplicação. |
| Bloco RyvallBlock SQL | Registro da cadeia da aplicação com armazenamento SQL. Seu modelo de autoridade difere do consenso soberano. |
| Quórum | Quantidade ou peso mínimo de assinantes elegíveis exigidos para uma decisão. No perfil de quatro validadores considerado aqui, o limiar é três. |
| Finalização | Aceitação de uma transição mediante todas as regras e certificados exigidos pelo perfil. Um HTTP 202 significa recepção, não finalização. |
| Troca de líder | Procedimento para mudar quem coordena propostas, conservando as regras de quórum e os registros necessários para recuperação. |
| Sincronização | Verificação e incorporação de dados ausentes por um nó. Copiar arquivos sem validar não constitui sincronização comprovada. |

## Criptografia, armazenamento e custódia

| Termo | Definição e critério observável |
|---|---|
| Assinatura | Verificação de autoria criptográfica para bytes específicos. Não comprova liquidez, saldo ou honestidade do signatário. |
| Assinatura híbrida | Perfil que exige os algoritmos especificados conjuntamente. O perfil implementado usa Ed25519 e ML-DSA-65; não se deve generalizar essa exigência para todo artefato histórico. |
| mTLS | Autenticação mútua do canal por certificados. Proteção do canal não substitui a assinatura nem as regras da transação. |
| WAL | Registro persistente para recuperação e reaplicação de operações. Sua leitura deve validar integridade e limites. |
| Snapshot | Estado persistido em uma posição identificável. Sua aceitação requer compromissos e validação adequados. |
| Custódia | Proteção e controle das chaves privadas, incluindo armazenamento, acesso, recuperação e revogação. Gerar uma chave não conclui esse processo. |
| Projeção | Visão derivada de outra fonte. Uma projeção SQL somente de leitura NÃO DEVE autorizar transferências VLOCK. |
| Prova Merkle | Evidência de associação a uma raiz segundo um esquema definido. Não estabelece valor financeiro. |

## Ativos e economia

| Termo | Definição e critério observável |
|---|---|
| Identidade de ativo | Unidade acompanhada de rede, regras de emissão e autoridade contábil. Símbolos iguais não provam ativos iguais. |
| SINDRA / SND | Unidade definida pela gênese VLOCK: nove casas decimais e oferta inicial de um bilhão. |
| NAET | Unidade da aplicação com seis casas decimais e operações no ledger SQL atual. |
| KWRK | Konaet Work: unidade de recompensa de trabalho no ledger SQL, com oito casas decimais. |
| KACT | Konaet Actum: unidade ligada à execução contabilizada no ledger SQL, com nove casas decimais. |
| NEXEL | Nome da unidade atômica de SND. Um SND corresponde a 1.000.000.000 unidades atômicas. |
| Money DNA | Política determinística de observação com compromissos criptográficos; no código atual não autoriza consenso nem modifica a oferta SND. |
| Capacidade de referência | Índice simbólico Money DNA de 8.888.888.888.888. NÃO DEVE ser apresentado como caixa, moeda emitida ou avaliação em reais. |
| Cotação | Observação de preço identificada por ativo, rede, fonte, moeda, par e horário. Um preço arbitrado manualmente não é uma negociação observada. |
| Liquidez | Quantidade efetivamente negociável sob condições documentadas de mercado. Não é deduzida da oferta total. |
| Faucet | Distribuidor limitado de unidades de uma rede de teste. Sua autoridade de débito e sua reserva devem estar explícitas. |

## Linguagem, provas e comunicação externa

| Termo | Definição e critério observável |
|---|---|
| `.ko` | Extensão de definições Konaet. Há manifestos declarativos e o perfil limitado de assertions `KONAET_KO_ASSERT_V1`, executável por um interpretador e ativado no consenso por gênese v6. Não é uma VM de propósito geral. |
| Runtime | Implementação que executa e valida regras. No caminho VLOCK atual, essa implementação é JavaScript. |
| Recibo de evidência | Registro do método, entradas, fonte, ambiente, resultado e limites de uma observação. Um hash é compromisso de integridade; não identifica sozinho quem produziu o dado. |
| Evidência local | Resultado em ambiente controlado por um único operador. Deve informar essa condição. |
| Reprodução independente | Execução por outra parte com entradas, código e critérios suficientes para conferir o resultado. |
| Ponte | Mecanismo entre redes com regras próprias de verificação e execução. Não existe equivalência monetária automática por adotar esse nome. |
| Origem / destino | Redes em que uma operação começa e produz seu efeito pretendido. Ambas precisam de identidade inequívoca. |
| Relayer | Transportador de mensagem ou prova. Transportar um dado não autoriza seu conteúdo. |
| Intent | Declaração de resultado desejado. Precisa de regras de autorização, execução e liquidação para produzir efeito. |
| Liquidação | Conclusão de obrigações segundo regras explícitas. Uma cotação ou interface não comprova sua execução. |

## Como ler termos externos

L1, L2 e L3 são classificações usadas por outros projetos. A identidade Konaet
Soberana não exige inventar uma posição hierárquica acima dessas redes.
Autonomia deve ser demonstrada pelas suas dependências de consenso e execução.
Este documento é original e mais específico ao projeto; sua extensão não é um
benchmark contra a rede Ethereum. Referência de vocabulário:
[Ethereum L2 interoperability nomenclature](https://github.com/ethereum/L2-interop/blob/main/NOMENCLATURE.md).

Uma alteração DEVE informar o termo afetado, sua razão, o estado de implementação
e os exemplos de aceitação e rejeição. Não deve redefinir retroativamente a
semântica de um evento já assinado.
