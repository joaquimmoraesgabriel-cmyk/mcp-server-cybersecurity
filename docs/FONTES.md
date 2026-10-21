# Fontes configuradas e cobertura

Revisão de 21/10/2026. Esta lista acompanha os 37 registros de `src/cyber_rag/source_registry.py` e o adaptador OWASP original: **38 fontes configuradas**. O catálogo em execução, obtido com `knowledge_catalog`, informa a configuração, os caminhos conhecidos, o cache e as falhas atuais. Estar configurada não comprova que uma fonte respondeu, que todos os arquivos foram coletados ou que o conteúdo está completo.

O snapshot inicial continua separado: 1.774 documentos das cinco fontes do piloto, com perfil `semantic`. `knowledge_search` consulta esse snapshot. `knowledge_research` também consulta os caches abaixo e a memória derivada. Coletar uma fonte por URL não a adiciona automaticamente ao snapshot, não gera vetores e não treina o modelo.

Na validação de 21/10/2026, 37 fontes retornaram amostras com evidências por URL/cache e pelo MCP; o MalAPI permaneceu indisponível. Esses resultados e as exclusões estão no [relatório de validação](../evaluations/results/2026-10-21-multisource-summary.json).

## Catálogo de consulta

Os exemplos são valores de `query`; use o ID na lista `source_ids`. Consulte uma fonte por vez durante a validação inicial e repita com `freshness="offline"` para verificar a cópia local. As URLs identificam as origens aprovadas: a ferramenta não aceita URLs livres. Os downloads de GitHub/GitLab usam a revisão efetivamente resolvida, fixada por commit; links gerais abaixo servem para identificar a fonte.

| ID | Escopo consultado | Exemplo de consulta | Limites e observações | Origem |
| --- | --- | --- | --- | --- |
| `owasp` | Cheat Sheet Series, arquivos Markdown em `cheatsheets/`. | `password storage` | Descoberta por nome; corpo pesquisável após coleta. Também integra o piloto. | [OWASP CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) |
| `attack` | Bundle STIX de ATT&CK Enterprise. | `T1059.001 PowerShell` | Arquivo agregado; sua contagem de cache não equivale à quantidade de técnicas. Também integra o piloto. | [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) |
| `sigma` | YAML de `rules/`, `rules-emerging-threats/` e `rules-threat-hunting/`. | `powershell encoded` | Somente texto; regras não são executadas. Também integra o piloto. | [SigmaHQ](https://github.com/SigmaHQ/sigma) |
| `cve` | Registro CVE JSON 5 por identificador. | `CVE-2021-44228` | Exige CVE exato; não baixa todos os CVEs. Também integra o piloto. | [CVE List V5](https://github.com/CVEProject/cvelistV5) |
| `kev` | Catálogo CISA Known Exploited Vulnerabilities em JSON. | `CVE-2021-44228` | Evidência de inclusão no catálogo, não diagnóstico de uma máquina. Também integra o piloto. | [CISA KEV](https://github.com/cisagov/kev-data) |
| `attack-mobile` | Bundle STIX de ATT&CK Mobile. | `T1407` | Separado de Enterprise e ICS; pesquisa no conteúdo agregado coletado. | [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) |
| `attack-ics` | Bundle STIX de ATT&CK ICS. | `T0800` | Separado de Enterprise e Mobile. | [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) |
| `d3fend` | Ontologia D3FEND em JSON. | `Network Traffic Filtering` | URL pública mutável; revisão local por hash. | [Ontologia oficial](https://d3fend.mitre.org/ontologies/d3fend.json) |
| `atlas` | Distribuição YAML mais recente dentro de `dist/v6/`. | `prompt injection` | A seleção é restrita à família v6 configurada; não descobre automaticamente outra versão principal. | [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data) |
| `capec` | Bundle STIX 2.1 de padrões de ataque CAPEC. | `CAPEC-66` | Um arquivo pode conter muitos padrões. | [MITRE CTI](https://github.com/mitre/cti) |
| `hacktricks` | Markdown em `src/`. | `sql injection` | CC BY-NC 4.0 e condições de terceiros; cache local, sem execução de exemplos. | [HackTricks](https://github.com/HackTricks-wiki/hacktricks) |
| `payloads` | Markdown do PayloadsAllTheThings. | `sql injection` | Referência textual; payloads nunca são executados. | [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| `internal-all-the-things` | Markdown em `docs/`, incluindo Active Directory. | `kerberos` | Licença geral de redistribuição não confirmada; exemplos não são executados. | [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) |
| `gtfobins` | Entradas em `_gtfobins/`. | `find` | Descrições e exemplos textuais de binários Unix; sem execução. | [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) |
| `lolbas` | Arquivos YAML em `yml/`. | `certutil` | Referências a binários Windows; sem execução. | [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) |
| `wadcoms` | Entradas em `_wadcoms/`. | `kerbrute` | Comandos documentados, sem executar ferramentas ou acessar ambientes. | [WADComs](https://github.com/WADComs/WADComs.github.io) |
| `loobins` | YAML em `LOOBins/`. | `osascript` | Binários de macOS; não é uma fonte de comandos Linux/Windows. Sem execução. | [LOOBins](https://github.com/infosecB/LOOBins) |
| `owasp-top10` | Top 10 Web 2025, Markdown em inglês. | `broken access control` | Seleção da edição 2025 em `2025/docs/en/`. | [OWASP Top10](https://github.com/OWASP/Top10) |
| `owasp-api` | API Security Top 10 2023, em inglês. | `broken object level authorization` | Seleção em `editions/2023/en/`. | [OWASP API Security](https://github.com/OWASP/API-Security) |
| `owasp-mobile` | Mobile Top 10 2024. | `improper credential usage` | A versão final de 2024 está no diretório upstream `2023-risks/`; edições antigas ficam fora. Licença específica de redistribuição não confirmada. | [OWASP Mobile Top 10](https://github.com/OWASP/www-project-mobile-top-10) |
| `owasp-llm` | Top 10 for LLM Applications 2025. | `prompt injection` | Arquivos selecionados em `2_0_vulns/LLM*`; sem indexação geral de todo o projeto. | [OWASP LLM Top 10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications) |
| `owasp-wstg` | Markdown de `document/` no ramo de desenvolvimento. | `sql injection` | Commit fixado da branch atual; não é uma edição publicada congelada. | [OWASP WSTG](https://github.com/OWASP/wstg) |
| `yara` | Regras `.yar`/`.yara` em diretórios selecionados de malware, packers, crypto, email e webshells. | `wannacry` | As regras não são compiladas nem executadas; não comprova eficácia de detecção. | [YARA-Rules](https://github.com/Yara-Rules/rules) |
| `atomic-red-team` | Definições YAML em `atomics/`. | `T1059.001` | Não executa testes nem baixa suas dependências e payloads. | [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) |
| `windows-events` | Páginas de eventos de auditoria do Windows 10 no Microsoft Learn. | `event 4624` | Exige Event ID exato de quatro dígitos. Alternativa explícita ao EventKB não identificado; documentação em `previous-versions`. | [Microsoft: evento 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) |
| `nvd` | Registro da API NVD 2.0 sem chave. | `CVE-2021-44228` | Exige CVE exato; revisão por registro e intervalo entre consultas. Preserva a distinção entre NVD e CVE Program. | [API NVD](https://nvd.nist.gov/developers/vulnerabilities) |
| `cwe` | Registro de fraqueza na API pública MITRE. | `CWE-79` | Exige identificador exato; não representa uma busca textual em todo o catálogo. | [MITRE CWE](https://cwe.mitre.org/data/downloads.html) |
| `exploit-db` | Descoberta pelo CSV oficial do GitLab e coleta de fontes textuais selecionadas. | `EDB-45233` | Aceita EDB-ID canônico, CVE ou descrição; exclui catálogo de shellcode e binários. Nada é executado. | [Exploit Database](https://gitlab.com/exploit-database/exploitdb) |
| `malapi` | Página oficial por nome exato de API Windows. | `VirtualAlloc` | **Indisponível na verificação de 21/10/2026 por falha de DNS; zero evidências.** Não há substituição silenciosa. | [MalAPI](https://malapi.io/) |
| `unprotect` | Descrições principais em `Techniques/*/description.txt` no repositório de contribuições. | `API Obfuscation` | 376 caminhos na descoberta registrada; não cobre todo o site. Exclui snippets, código, regras e binários; licença aberta geral não confirmada. | [Unprotect ContributeV2](https://github.com/Unprotect-Project/ContributeV2) |
| `capa` | Regras textuais dos diretórios selecionados do CAPA. | `check for debugger via API` | 1.055 caminhos na descoberta registrada; inclui experimentais em `nursery/`. Não compila nem executa regras. | [Mandiant CAPA Rules](https://github.com/mandiant/capa-rules) |
| `vx-papers` | Lista explícita de 15 artigos: 14 PDFs e um TXT. | `enumerate processes` | Não é todo o corpus VX. Sem binários, implementações, OCR ou execução; direitos variam por artigo. | [VXUG-Papers](https://github.com/vxunderground/VXUG-Papers) |
| `nist-csf` | Catálogo eletrônico OSCAL do NIST CSF 2.0. | `GV.OC` | Versão do catálogo OSCAL pode diferir da edição do framework; preserve os metadados. | [NIST OSCAL Content](https://github.com/usnistgov/oscal-content) |
| `nist-800-53` | Catálogo OSCAL SP 800-53 Rev. 5, incluindo procedimentos SP 800-53A identificados na origem. | `Account Management` | Commit e metadados identificam a versão exata; não certifica conformidade. | [NIST OSCAL Content](https://github.com/usnistgov/oscal-content) |
| `cis-controls` | CIS Controls v8 Assessment Specification, páginas Control 1 a Control 18. | `Control 1 inventory` | Exige número de controle; termos CC BY-NC-ND 4.0. Não representa todos os produtos CIS nem certifica conformidade. | [CIS CAS](https://cas.docs.cisecurity.org/en/latest/) |
| `lgpd` | Texto atualizado da Lei 13.709/2018 publicado pela Câmara dos Deputados. | `LGPD princípios dados pessoais` | Fonte oficial explicitamente identificada em lugar do endpoint Planalto indisponível. Hash/data identificam a cópia; não garante todas as alterações posteriores. | [LGPD na Câmara](https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-normaatualizada-pl.html) |
| `gdpr` | Publicações em inglês: original de 2016 e texto consolidado identificado com corrigendum de 2018. | `Article 5 personal data` | Publicações fixas no Cellar; atualizar o cache não descobre automaticamente novas alterações legais. | [GDPR no EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) |
| `iso27001` | **Somente metadados abertos** de edições e suplementos ISO/IEC 27001. | `ISO 27001` | Projeção do CSV oficial; não inclui texto normativo, requisitos ou Annex A. ODC-By 1.0 com atribuição. | [ISO Open Data](https://www.iso.org/open-data.html#iso_deliverables_metadata) |

## Fontes de governança, normas e legislação

`nist-csf` e `nist-800-53` usam os arquivos OSCAL cadastrados no repositório oficial. A edição do framework ou da norma, a versão de seu catálogo eletrônico e a revisão Git são campos distintos. Uma evidência recuperada não estabelece a conformidade de uma organização.

`cis-controls` consulta a especificação pública de avaliação CAS, com identificador `Control 1` a `Control 18`. A cópia original e o texto derivado são identificados separadamente; os [termos CC BY-NC-ND 4.0](https://cas.docs.cisecurity.org/en/latest/source/terms-of-use/) continuam aplicáveis. A licença MIT deste servidor não altera os termos do conteúdo.

`lgpd` usa a versão atualizada publicada pela Câmara dos Deputados. Essa escolha é explícita: o endpoint do Planalto esteve indisponível durante a integração. A fonte, o hash e a data de coleta devem acompanhar a citação; o servidor não interpreta a lei nem comprova que todas as alterações futuras foram incorporadas.

`gdpr` consulta diretamente duas publicações oficiais do serviço público Cellar da União Europeia:

- `gdpr-original-en.html`: [publicação original de 2016 em inglês](https://publications.europa.eu/resource/cellar/3e485e15-11bd-11e6-ba9a-01aa75ed71a1.0006.03/DOC_1).
- `gdpr-consolidated-en.html`: [publicação consolidada identificada na origem como 04.05.2016, com corrigendum de 2018](https://publications.europa.eu/resource/cellar/5f2552c2-cc45-11e6-ad7c-01aa75ed71a1.0022.03/DOC_1).

Esses caminhos representam publicações determinadas. `freshness="refresh"` verifica seus bytes, mas não descobre uma publicação jurídica mais recente. Preserve o [aviso legal da União Europeia](https://eur-lex.europa.eu/content/legal-notice/legal-notice.html?locale=en) e a atribuição da fonte consolidada.

`iso27001` usa o [CSV oficial de metadados ISO](https://isopublicstorageprod.blob.core.windows.net/opendata/_latest/iso_deliverables_metadata/csv/iso_deliverables_metadata.csv), distribuído sob [ODC-By 1.0](https://opendatacommons.org/licenses/by/1-0/) com atribuição. O arquivo inteiro é preservado localmente para integridade; a representação pesquisável seleciona apenas os registros de ISO/IEC 27001, suas edições e suplementos. O download é grande: 60.058.790 bytes na validação de 21/10/2026, com limite configurado de 96 MiB. Naquela cópia, 81.670 registros foram examinados e sete registros ISO/IEC 27001 selecionados; isso não equivale a sete normas completas.

O transporte específico da ISO faz `HEAD` e até oito faixas paralelas, exigindo ETag forte, `If-Match`, `Content-Range` e tamanho consistentes. Só entrega o original após reunir e verificar todas as partes; não publica conteúdo parcial. Seu orçamento é de até 90 segundos, limitado também pelo prazo restante de 90 segundos compartilhado pela pesquisa. A primeira coleta observada levou 54,89 segundos nesta conexão, com reutilização e consulta offline verificadas; esse tempo não é uma previsão nem garantia para outra execução. Não há troca automática para JSONL. Confira estágio, edição, relações de substituição e data dos metadados antes de citar. **O conector não fornece o texto completo da norma nem autoriza sua redistribuição.**

## Interpretação dos estados e reutilização

`known_paths` mede caminhos conhecidos; `cached_versions` mede versões armazenadas. Nenhum deles é uma medida de qualidade, quantidade de entidades ou cobertura semântica. Um catálogo agregado pode gerar um arquivo no cache com muitos registros; uma fonte indisponível pode permanecer configurada e ter zero evidências.

As fontes Git usam commits fixados. APIs por registro e URLs HTTP preservam os bytes recebidos e o SHA-256; isso não torna a URL remota imutável. `current` significa que a evidência satisfaz a política de verificação, não que o conteúdo esteja factualmente correto ou juridicamente atualizado. Falhas, revisões e datas devem acompanhar a resposta do cliente.

A licença do servidor cobre o código do servidor. Os termos de cada fonte e de conteúdos de terceiros continuam aplicáveis. A instalação baixa as evidências para o cache local; este repositório não distribui o corpus. Consulte os [limites de pesquisa, memória e PDF](PESQUISA_SOB_DEMANDA.md) e o [roteiro de validação no cliente](CONECTAR_CODEX.md).
