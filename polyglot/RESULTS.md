# Conformidade executada: nove entradas para .ko

Os nove jobs do [workflow 41222093406](https://github.com/7dsol3/konaet-sovereign-spec/actions/runs/41222093406)
terminaram com sucesso no Ubuntu 24.04. Fonte medido:
`91ce48e4b45a102c5f01bf97b84011fc573bc819`.
Os clientes não foram modificados ao incluir os relatórios na distribuição.

| Entrada | Ferramenta observada | Vetores canônicos | Cálculos e comparações | Frames inválidos rejeitados | Finalização .ko |
|---|---|---:|---:|---:|---|
| C | Clang 18.1.3 | 12 | 37 | 20 | Certificado conferido |
| C++ | Clang 18.1.3 | 12 | 37 | 20 | Certificado conferido |
| C# | .NET SDK 10.0.403, alvo net8.0 | 12 | 37 | 20 | Certificado conferido |
| Python | 3.12.3 | 12 | 37 | 20 | Certificado conferido |
| Rust | Cargo/rustc 1.85.1 | 12 | 37 | 20 | Certificado conferido |
| Perl | 5.38.2 | 12 | 37 | 20 | Certificado conferido |
| Go | 1.24.13 | 12 | 37 | 20 | Certificado conferido |
| Shell | POSIX sh → C / Clang 18.1.3 | 12 | 37 | 20 | Certificado conferido |
| Node | 24.22.2 | 12 | 37 | 20 | Certificado conferido |

Cada job criou uma gênese e chaves de teste próprias, implantou o registro,
enviou uma chamada com os argumentos produzidos pelo cliente e conferiu
a transição e o certificado de quórum. Foram quatro processos por job,
não quatro operadores administrativamente independentes.

As 37 verificações cobrem os modos de cálculo, correspondência e divergência
dos 12 vetores e uma entrada no limite de 16 KiB. O cliente devolve status
1 na divergência esperada: isso faz parte do teste aprovado.
C e C++ passaram com AddressSanitizer e UndefinedBehaviorSanitizer.
O build Rust aceitou o grafo de dependências com `--locked`.

Os nove artefatos foram baixados, seus digests comparados aos do GitHub
e seus certificados novamente verificados em uma máquina Windows fora
dos jobs. Os [JSONs completos e sua proveniência](../evidence/polyglot-2026-10-31/provenance.json)
ficam na distribuição, incluindo o bundle de finalização de cada job.
`npm run verify` e os testes reexecutam essa conferência criptográfica.

Também houve execução local Windows de Python 3.12.10, .NET SDK 8.0.422,
Perl 5.42.3 e Go 1.26.10, com os mesmos critérios. Esses runs locais são
complementares; a tabela acima identifica os relatórios publicados.

## Escopo da conferência

O cliente em cada linguagem calcula o compromisso e seus argumentos.
A verificação completa do certificado e a reexecução do consenso são feitas
pelo verificador Node existente. Os vetores públicos são sintéticos;
seus salts não são usados em dados privados.

Wikitext e TeX descrevem o protocolo e não são contados como clientes
executáveis. Shell compartilha a implementação C. Este conjunto não mede
TPS, não é comparação de desempenho com outras redes e não publica uma
nova rede permanente.

## Correções registradas

Na preparação local, a expressão de saída do cliente Perl tinha precedência
incorreta: uma comparação correta saía com status 1. O ternário foi
parentizado; os três modos e a integração foram então aprovados.

O primeiro workflow usava `runner.temp` no escopo de ambiente do job e não
chegou a executar os clientes. O caminho passou a ser resolvido no step;
a nova execução completou os nove jobs. A tentativa original permanece
no histórico, sem ser contada como conformidade aprovada.
