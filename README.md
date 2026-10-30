# Konaet Soberana

**Especificação pública · edição 1.1.0**

Regras próprias. Termos precisos. Recibos verificáveis.

A Konaet Soberana é o projeto de uma rede com protocolo, identidade, estado e
validadores próprios. Este repositório publica sua nomenclatura, o perfil de um
evento VLOCK7SIN e verificações que qualquer pessoa pode executar sem conta,
banco de dados, chave de produção ou dependências npm.

**Esta é uma edição da documentação e do verificador de exemplos. A rede atual
tem validação local; este repositório não anuncia uma mainnet operante.**

| Documento | O que entrega |
|---|---|
| [Nomenclatura](NOMENCLATURE.md) | Identidade, consenso, ativos, provas, operações e interoperabilidade |
| [Protocolo](PROTOCOL.md) | Bytes, domínios, assinatura e invariantes do exemplo público |
| [Runtime .ko](KO-RUNTIME.md) | Compilador e interpretador de assertions, API pública e ativação no perfil v6 |
| [Evidências](EVIDENCE.md) | O que foi observado, quem pode reproduzir e o que falta |
| [Comparação](COMPARISON.md) | Critérios para comparar redes com a mesma carga e hipótese de segurança |
| [Operação](DEPLOYMENT.md) | Caminho para uma rede entre máquinas e uma entrada pública |
| [Segurança](SECURITY.md) | Limites do verificador e comunicação de problemas |

## Verifique agora

Com Node.js 24.7 ou superior da série 24:

```sh
git clone https://github.com/7dsol3/konaet-sovereign-spec.git
cd konaet-sovereign-spec
npm test
npm run verify
```

Não é necessário instalar pacotes. Os testes adulteram bytes, assinaturas,
rede, campos e checksum para conferir a rejeição. O comando `verify` valida a
assinatura Ed25519, o identificador e a codificação do vetor sintético, além
dos hashes do pacote documental. **Assinatura válida não comprova saldo,
inclusão ou finalização por validadores.**

## O que já existe

- VLOCK7SIN implementa eventos assinados, estado Merkle, persistência e
  finalização por quórum. Há testes locais de troca de líder e sincronização.
- O perfil de operadores oferece identidades separadas e transporte mTLS;
  perfis híbridos usam Ed25519 e ML-DSA-65. A operação independente em outras
  máquinas ainda requer instalação e evidência.
- `.ko` possui definições declarativas e um novo perfil executável limitado,
  `KONAET_KO_ASSERT_V1`, incluído nesta edição. O perfil v6 vincula a política à
  gênese e a executa nos validadores. As redes anteriores conservam suas regras.
- SND é a unidade da gênese VLOCK. NAET, KWRK e KACT têm operações no ledger
  SQL da aplicação; sua presença na interface não os transforma em unidades
  do consenso VLOCK.

O código integral do nó não é distribuído aqui. O verificador público foi
escrito para conferir um perfil específico de evento e não substitui o nó.
Os limites e estados de implementação estão em [EVIDENCE.md](EVIDENCE.md).

O [runtime .ko online](https://konaet-ko-runtime.alkalipixie.chatgpt.site) compila
e executa assertions sobre o contexto enviado. Esse serviço não hospeda
validadores nem finaliza transferências. O motor correspondente está em
[runtime/ko-policy.cjs](runtime/ko-policy.cjs), sem dependências npm.

## O puzzle do dia

![Meme: um engenheiro cercado por peças L1, L2 e L3 pergunta “Mais uma camada?”; outro segura um cubo .ko e pergunta “Cadê o recibo?”.](assets/puzzle-do-dia.png)

Uma provocação sobre debates técnicos, produzida com geração de imagem.
**Meme ≠ benchmark.** A referência visual ao Ethereum não implica parceria,
endosso ou demonstração de superioridade. A proposta da Konaet é fazer cada
afirmação vir acompanhada de um critério verificável.

## Autoria e uso

Projeto de [7dsol3](https://github.com/7dsol3). Texto e verificador desta edição
sob [licença ISC](LICENSE). A nomenclatura é original; a documentação Ethereum
é citada como referência para comunicação entre projetos, sem afiliação.

Propostas de melhoria devem apresentar a regra, seu estado de implementação,
um exemplo aceito e um exemplo rejeitado. Veja [CONTRIBUTING.md](CONTRIBUTING.md).
