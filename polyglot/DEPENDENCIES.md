# Dependências e atribuições

O código de integração deste kit mantém a [licença ISC](../LICENSE) e a
atribuição Adilson Oliveira / 7dsol3. Isso não atribui à Konaet autoria
sobre SHA-256, os compiladores ou as bibliotecas utilizadas.

| Componente externo | Uso | Origem e licença |
|---|---|---|
| OpenSSL | SHA-256 via EVP nos clientes C e C++ | [Projeto e licença](https://github.com/openssl/openssl/blob/master/LICENSE.txt), Apache-2.0 nas versões 3 |
| RustCrypto sha2 0.10.9 | SHA-256 no cliente Rust | [Projeto](https://github.com/RustCrypto/hashes/tree/master/sha2), MIT ou Apache-2.0 |
| Bibliotecas padrão Python, Go e .NET | Hash, inteiros e I/O | Mantêm as licenças das respectivas distribuições |
| Módulos Perl Digest::SHA, JSON::PP e Math::BigInt | Hash, serialização e inteiros | Mantêm suas licenças originais; distribuídos com Perl |
| Node.js | SDK canônico, harness e verificador de consenso | Licença incluída na distribuição Windows |

`rust/Cargo.lock` fixa versões e checksums de todas as dependências do
cliente Rust. O build usa `cargo --locked`; o resolvedor não pode trocar
silenciosamente esse grafo. Dependências externas não são rebatizadas.

Os compiladores e runtimes necessários são obtidos pelos seus canais de
distribuição. Este kit não baixa executáveis durante o uso do cliente e
não inclui bibliotecas nativas de terceiros no código-fonte.
