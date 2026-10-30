# Segurança

Este repositório contém documentação e um verificador de exemplo, não um nó de
produção, carteira, serviço de custódia ou distribuidor de moeda.

O verificador aceita somente o perfil EVENT/js-v1 descrito. Confere bytes,
limites, endereço do remetente, assinatura, checksum e identificador. Não
consulta saldo, raiz reconhecida por uma rede, nonce atual, inclusão ou quórum.
Uma pessoa com chave própria pode assinar uma transação sem saldo; passar no
verificador não torna essa transação executável ou finalizada.

O manifesto não está assinado. Confere consistência do conjunto, sem atestar
quem o produziu. Os resultados anteriores do sistema são autorrelatados pelo
mantenedor e não substituem uma reprodução independente.

Para problemas sem informação sensível, abra uma issue com versão, entradas
sintéticas, passos e resultado esperado. Para vulnerabilidades sensíveis, use
o canal privado de advisories do repositório quando disponível. Nunca anexe
chaves, credenciais ou dados reais em um relatório público.

Artefatos suportados nesta edição: documentação e verificador versão 1.0.0.
