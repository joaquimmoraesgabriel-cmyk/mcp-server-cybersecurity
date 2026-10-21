# Fontes e atribuição do piloto

O código oferece conectores; o corpus e os modelos não fazem parte da distribuição do repositório. Cada instalação baixa os arquivos diretamente das fontes oficiais. A licença do projeto não substitui as condições de terceiros.

O primeiro piloto real foi obtido em **20 de outubro de 2026**, no fuso America/Sao_Paulo. A revisão de cada repositório foi resolvida antes dos downloads. O manifesto local registra o instante UTC de verificação, a seleção, a revisão e o SHA-256 de cada arquivo. Os downloads foram concluídos; aprovação do software depende dos testes registrados separadamente.

| Fonte | Revisão congelada do primeiro piloto | Seleção e atribuição |
| --- | --- | --- |
| [MITRE ATT&CK Enterprise](https://github.com/mitre-attack/attack-stix-data) | `c2494b29dd268c46a5d0ea0990553e4327cd2253` | Bundle Enterprise original preservado; somente T1059, T1059.001 e a relação entre elas indexadas, além do README. A licença exige a reprodução do aviso MITRE e da licença nas cópias; ambos são preservados em `LICENSE.txt`. [Licença no snapshot](https://github.com/mitre-attack/attack-stix-data/blob/c2494b29dd268c46a5d0ea0990553e4327cd2253/LICENSE.txt). |
| [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries) | `c366393214da5ae186a7a06a27dade7617987304` | Cinco cheat sheets: SQL Injection, XSS, armazenamento de senhas, upload de arquivos e SSRF. `LICENSE.md` preservado, com CC BY-SA 4.0 e atribuição à OWASP e aos autores do projeto. [Licença no snapshot](https://github.com/OWASP/CheatSheetSeries/blob/c366393214da5ae186a7a06a27dade7617987304/LICENSE.md). |
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | `773f8d1bd92f575002aabe62c64e0932bb7fac94` | Uma regra de criação de processos PowerShell, ID `b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c`, com autoria e referências intactas; README e aviso `LICENSE` preservados. As regras seguem a Detection Rule License 1.1 apontada pelo aviso da fonte; não devem ser rotuladas como MIT. [Aviso no snapshot](https://github.com/SigmaHQ/sigma/blob/773f8d1bd92f575002aabe62c64e0932bb7fac94/LICENSE), [licença referenciada](https://github.com/SigmaHQ/Detection-Rule-License). |
| [CVE Project](https://github.com/CVEProject/cvelistV5) | `565af88a49a2d7eabfa12905caa1b05171fc603e` | Apenas CVE-2021-44228 e README. Os containers CNA e ADP são preservados com seus provedores; não há enriquecimento NVD neste piloto. O README conserva a referência aos [termos do programa CVE](https://www.cve.org/Legal/TermsOfUse). |
| [CISA KEV](https://github.com/cisagov/kev-data) | `3de597fd70382f1f09acb09bf5e15dca4fa22678` | Catálogo completo `2026.10.20`, publicado pela fonte em `2026-10-20T19:00:31.8765Z`, com 1.754 entradas; README e `LICENSE` preservados. CC0 1.0 conforme a licença da fonte, com ressalvas próprias para links de terceiros e marcas. [Licença no snapshot](https://github.com/cisagov/kev-data/blob/3de597fd70382f1f09acb09bf5e15dca4fa22678/LICENSE). |

A coleta inicial ocupa aproximadamente 57 MB em arquivos de origem, antes dos índices e dos arquivos normalizados. O bundle Enterprise representa a maior parte desse tamanho. Essa medida não é um requisito mínimo de RAM ou disco nem uma promessa de tamanho para futuras revisões.

## Preservação e limites

- Os arquivos originais e avisos são preservados byte a byte, com hash. Bundles e catálogos são guardados como arquivos de origem e não entram diretamente no ranking de busca.
- Objetos STIX e entradas KEV derivados recebem uma serialização JSON normalizada, identificada por `raw_representation=normalized_object`; `archive_path`, `original_locator` e `source_file_sha256` ligam cada registro ao original completo. Essa representação não é apresentada como um recorte de bytes idêntico ao arquivo de origem.
- Regras Sigma e documentos Markdown preservam integralmente seus bytes, inclusive código e referências. Nada é executado durante a ingestão.
- O piloto não contém a união de CVEs do KEV com os últimos 90 dias prevista na especificação. Sua cobertura é explicitamente reduzida para validar o funcionamento inicial.
- A documentação explicativa incluída consiste nos READMEs selecionados. Ela ainda não cobre toda a semântica dos schemas, regras e catálogos exigida pela versão futura.
- O NVD tem parser opcional para envelopes API 2.0, mas não é baixado pelo piloto padrão. Uma ausência local nunca prova que uma informação não exista em outra fonte.
- Referências externas dentro do conteúdo não são seguidas automaticamente. O aviso de licença Sigma preservado contém a referência à DRL; o texto separado dessa licença não é baixado pelo conector atual.
- Antes de redistribuir corpus, índices, pesos ou materiais transformados, devem ser conferidas as condições específicas dos materiais envolvidos. O primeiro piloto distribui conectores e referências, não esses conteúdos.

## Gabarito do piloto

O arquivo `evaluations/pilot.json` contém onze verificações determinísticas: identidades exatas, hierarquia ATT&CK, separação CVE/KEV, mapeamento Sigma, reconstrução de bytes, busca textual e ausência no escopo local. Seus oráculos foram conferidos nos bytes das revisões listadas acima. O hash esperado da regra Sigma é `b88a027bdbd78d16f72c07bfad6b7b8c44b485ada030b7320b656a72cb8b9934`, para 1.565 bytes.

O gabarito exige as revisões de `source_revisions`, conferidas pelo runner antes dos casos, e mantém `snapshot_id: null`. Isso permite reindexar os mesmos arquivos e a mesma seleção em outra geração local ou instalação. O relatório registra o UUID efetivamente consultado; opcionalmente, um `snapshot_id` não nulo pode restringir a avaliação a uma geração específica. Fonte ausente ou revisão divergente causa falha. Os onze casos não substituem o benchmark de 30 perguntas, a avaliação semântica multilíngue, a homologação de clientes ou a verificação de respostas geradas por GPT e Claude.

A primeira execução ficou vinculada ao snapshot `d5cd628b5e5b480ea817c34ba02b11ab`, publicado em 20 de outubro de 2026 às 22:47:07 no fuso America/Sao_Paulo. Foram armazenados 1.774 documentos, 1.949 trechos e 1.757 entidades, sem arquivos em quarentena. As onze verificações determinísticas passaram no perfil lexical; o relatório local foi salvo em `data/evaluation-pilot.json`. Documentos incluem originais de arquivo e avisos, que são preservados mas excluídos do ranking.
