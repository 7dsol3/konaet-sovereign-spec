# Contribuir

Abra uma issue para discutir um termo, perfil ou resultado. Propostas devem
informar a motivação, o estado atual e a diferença pretendida. Separe alterações
editoriais de mudanças em bytes ou regras de consenso.

Para enviar uma alteração:

1. Atualize o texto afetado e seus exemplos.
2. Execute `npm test`.
3. Se mudou arquivos distribuídos, execute `npm run manifest`.
4. Execute `npm run verify` e revise o diff do manifesto.

Isso também vale para edições do README pela interface do GitHub: o README
participa do inventário de integridade. Uma edição sem atualizar o manifesto
faz o CI recusar a publicação. Mantenha mudanças de documentação e o
respectivo manifesto no mesmo commit. Imagens que já existem em `assets/`
podem ser referenciadas diretamente, inclusive nos pacotes offline.

O manifesto cobre os arquivos distribuídos, exceto `.git`, `node_modules` e
ele próprio. O verificador também recusa caminhos não previstos e nomes de
segredos. Não inclua contas, tokens, seeds, dumps ou credenciais em issues.

Uma alteração em formato deve ter casos positivos e negativos. O campo de
perfil não deve ser ampliado para aparentar suporte que o verificador não tem.
Medições exigem entradas, ambiente, amostras, falhas e limites.
