# KONAET BTC Lab — operação local e verificável

O núcleo C#/.NET 8, catálogo e vetores foram importados, sem alterações,
do BTC Lab fornecido pelo mantenedor no workspace. [source-lock.json](source-lock.json)
registra cada hash de origem. Aplica-se a [licença ISC do projeto](../LICENSE).
Não se atribui a esta integração a invenção de secp256k1, SHA-256 ou Bitcoin.

## Executar no Windows

Instale o SDK .NET 8 e execute na pasta da especificação:

```powershell
./btc-lab/Start-KonaetPuzzle.ps1 -ValidateOnly
./btc-lab/Test-KonaetWorker.ps1
./btc-lab/Start-KonaetPuzzle.ps1 -Minutes 10
```

O launcher compila o núcleo, confere seus hashes e pesquisa um trecho do
**puzzle público #71**, no intervalo `[2^70, 2^71)`, usando um worker de
baixa prioridade. O início é sorteado na primeira sessão; as seguintes
retomam o checkpoint. A sessão encerra em até dez minutos por padrão,
com timeout de dez segundos por processo. O máximo configurável é 60 minutos.
Não instala serviço nem inicia automaticamente com o Windows.

O estado fica na pasta de dados local do usuário, em
`Konaet/PuzzleWorker/state`. `checkpoint.json` registra somente intervalos
inteiramente conferidos. Um resultado parcial mantém o início para repetir
o trecho; a contagem agregada nunca é interpretada como prefixo completo.
`worker.lock` impede sessões simultâneas no mesmo estado. Crie um arquivo
`STOP` nessa pasta para encerrar ao fim do trecho atual; remova-o para retomar.

Uma eventual solução fica em `solution.dpapi`, cifrada por Windows DPAPI
para o usuário atual. O launcher não imprime a chave, não faz upload do
estado, não monta ou transmite transações e encerra a busca ao detectar o
arquivo protegido. `session.json` contém apenas o resumo público da sessão.
Não publique a pasta de estado, o arquivo protegido ou saídas cruas de
`solve-chunk`, pois essa operação interna pode devolver material privado.

## Limites do experimento

O #71 contém `1.180.591.620.717.411.303.424` candidatos. Terminar um trecho não
é resolver o puzzle. A probabilidade de uma busca uniforme que examina `k`
candidatos distintos é `k / 2^70`, sob a hipótese de chave uniforme no intervalo.
Taxa local e duração observada devem acompanhar qualquer estimativa de tempo.
Não há promessa de prêmio, renda, redução mágica do espaço ou vantagem quântica.

[BTC Puzzle](https://btcpuzzle.info/) publica o desafio e o endereço
`1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`. O catálogo é um snapshot de
08/11/2026; saldo e status atuais exigem nova consulta pública. Nenhuma
carteira dormente é convertida em alvo deste launcher. A autorização do
desafio não autoriza acessar outras carteiras.

## Testes e núcleo existente

O CI usa o `selftest` original: vetores de campo, curva, hash, Base58, puzzles
já resolvidos, regras de consulta e auditoria do binário. O supervisor tem
regressões próprias para precisão acima de `2^53`, trechos parciais,
identidade errada, contagem incompatível e limites de inteiros.

Buscas por recompensas não rodam no CI. O launcher recusa essa execução
quando `GITHUB_ACTIONS=true`. A infraestrutura do GitHub é usada para
engenharia e evidências, respeitando seus
[limites de uso](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies).
