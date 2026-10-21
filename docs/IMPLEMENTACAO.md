# Implementação local e extensão sob demanda

Alfa local `0.1.0a1`, desenvolvida no Windows com Python 3.12.14. Este documento separa o comportamento implementado dos ensaios históricos; a [especificação](ESPECIFICACAO_RAG_MCP.md) continua sendo o alvo mais amplo.

## Pesquisa multifontes e memória

A implementação preserva o snapshot semântico e acrescenta caches por fonte e memória derivada, descritos em [Pesquisa sob demanda](PESQUISA_SOB_DEMANDA.md). São dez ferramentas: as cinco consultas originais, `knowledge_catalog`, `knowledge_research`, `knowledge_get_cached_document`, `knowledge_remember` e `knowledge_forget`.

`knowledge_search` continua restrito ao snapshot. `knowledge_research` reúne snapshot, caches de fontes e notas em camadas identificadas. A configuração reúne 38 fontes, incluindo OWASP, ATT&CK, Sigma, CVE e KEV, com escopos documentados em [Fontes](FONTES.md). O catálogo em execução é a referência para IDs, URLs, formato, exemplos, cobertura e restrições; sua lista não representa disponibilidade atual ou documentos já coletados. Os caches usam SQLite/FTS5 e não reconstroem E5/Qdrant por pergunta.

A descoberta depende do formato: caminhos e aliases em repositórios, arquivos agregados ou consulta por ID exato. Repositórios usam revisão fixada; URLs HTTP preservam cópias locais com hash, sem promessa de imutabilidade da origem. NVD, CWE e eventos Windows têm revisão e data por registro. A alternativa Microsoft `windows-events` não é o EventKB, cuja origem ainda não foi confirmada. Materiais com acesso ou licenciamento pendente não devem ser anunciados como operacionais apenas por constarem no plano inicial.

Na descoberta verificada em 21/10/2026, `unprotect` selecionou 376 descrições principais do repositório oficial de contribuições, e `capa`, 1.055 regras textuais, incluindo as experimentais em `nursery/`. `vx-papers` restringe o acesso a 15 artigos explicitamente permitidos: 14 PDFs e um TXT. São escopos de descoberta, não cópias completas desses acervos. O conector `malapi` está configurado, mas a origem oficial apresentou falha de DNS e forneceu zero evidências na verificação; não foi usada uma alternativa silenciosa. O [detalhamento de cobertura](PESQUISA_SOB_DEMANDA.md#catálogo-e-descoberta) mantém as restrições e os avisos de licença.

Em GRC, foram configurados os catálogos OSCAL NIST CSF 2.0 e SP 800-53 Rev. 5; CIS Controls CAS v8 por controle; LGPD atualizada na Câmara; publicações original e consolidada do GDPR no Cellar; e metadados abertos da ISO/IEC 27001. O texto normativo ISO não é coletado. As publicações GDPR são fixas, de 2016 e com corrigendum de 2018, e não asseguram descoberta de alterações posteriores. A [descrição por fonte](FONTES.md#fontes-de-governança-normas-e-legislação) separa origem, edição e restrições de uso. Esses cadastros não são uma contagem de validações aprovadas.

`auto`, `refresh` e `offline` controlam a rede. Atualmente CVE/NVD/KEV têm TTL de uma hora e a maioria das demais fontes, 24 horas; o catálogo publica a política de cada fonte. Até três fontes podem ser consultadas online por chamada, ou até 64 filtros offline. A pesquisa compartilha orçamento de 90 segundos e 24.000 caracteres de evidências. Estados, falhas e quotas são informados por fonte. O teto global de cache de 4 GiB é conferido antes de cada fonte e pode ser ultrapassado por uma operação; coletas seguintes usam apenas o conteúdo local.

A memória recebe somente notas explicitamente submetidas com referências verificáveis. Todas são `derived_unverified`, têm prazo e limites, e são omitidas quando suas evidências deixam de ser atuais. Ela não captura conversas nem treina modelos. Clientes que usam o mesmo diretório de dados compartilham as notas.

A configuração do adaptador participa da validação do cache. Quando ela muda, evidências incompatíveis ficam `unknown` até nova verificação/coleta. O recarregamento da mesma revisão atualiza texto, índice e atribuição, preservando identidade e bytes originais; alteração desses bytes sob a mesma revisão provoca `CACHE_INTEGRITY`. Na validação de referências do snapshot, uma observação mais antiga do cache não invalida uma evidência verificada depois apenas por ter outra revisão.

A espera de rede usa trava separada da consulta vetorial. Os endpoints permanecem locais e autenticados; não foram acrescentadas ferramentas de shell, scanner, execução de documentos ou administração dos snapshots. O núcleo anuncia `tool_contract: 3`; atualizar uma instalação exige reiniciar o núcleo e redescobrir as ferramentas no cliente, sem reimportar a base.

## Parser PDF e sua validação específica

`pypdf` 6.21.2 extrai texto em processo Python separado, com até 512 MiB de memória e dez segundos, respeitando o prazo restante da pesquisa. Os limites são de processo e recursos, não uma sandbox de segurança. A entrada é limitada a 16 MiB e 100 páginas; o texto derivado, a 2 MiB. Há teto de 8 MiB por stream e 32 MiB de bytes decodificados no documento, incluindo Forms e fontes. Conteúdo ativo, anexos e links não são executados ou abertos.

PDFs criptografados e documentos sem texto pesquisável são recusados; OCR não está incluído. O texto pode perder layout e omitir conteúdo presente apenas em imagens. Metadados identificam a representação derivada e a quantidade de páginas com e sem texto; os bytes originais continuam preservados. Avisos do parser e falhas dentro de Forms não são convertidos em sucesso parcial. Veja os [detalhes dos limites](PESQUISA_SOB_DEMANDA.md#extração-de-texto-de-pdf).

Na rodada específica de 21/10/2026, **31 testes do parser passaram no Windows** com `pypdf` 6.21.2; Ruff também passou nos três arquivos dessa implementação. Os testes exercitaram limite de memória imposto pelo Job Object, encerramento e coleta do processo após prazo, preservação da interface controlada de erros, criptografia, ausência de texto e expansão de conteúdo comprimido, inclusive dentro de Forms. A implementação POSIX com `RLIMIT_AS` não foi executada nessa rodada. Esse resultado não é o total da suíte multifontes nem uma validação de cada PDF do catálogo.

## Validação específica da fonte ISO

Em 21/10/2026, a primeira coleta do CSV oficial ISO recuperou 60.058.790 bytes em 54,89 segundos nesta conexão. A reutilização do cache e a consulta offline também passaram. O parser examinou 81.670 registros e selecionou sete de ISO/IEC 27001, suas edições e suplementos; o original completo foi preservado, sem extrair o texto normativo.

O transporte usa `HEAD` e até oito faixas paralelas, com ETag forte, `If-Match`, `Content-Range` e tamanhos verificados, sem publicar resultado parcial. O adaptador tem teto de 96 MiB e até 90 segundos, limitado pelo prazo restante compartilhado da pesquisa. As demais fontes novas mantêm o padrão de 30 segundos. O tempo observado é uma medida dessa coleta, não duração esperada ou garantia de desempenho. Essa validação específica não substitui a repetição final da suíte e dos ensaios MCP.

## Reproduzir a validação multifontes

Execute na raiz do projeto, com as dependências instaladas. O [ensaio por URL](../evaluations/validate_source_urls.py) consulta a amostra configurada de cada registro novo, em sequência: coleta `auto`, leitura do original, reutilização sem nova requisição e repetição offline de todas as fontes anteriores. Ele para ao falhar; usa diretório isolado e não percorre todo o corpus upstream. OWASP é exercitado pelo ensaio MCP seguinte.

```powershell
.\.venv\Scripts\python.exe .\evaluations\validate_source_urls.py --data-dir .\.local-data\multisource-validation --report .\.local-data\multisource-validation-report.json --skip malapi
```

O [ensaio MCP](../evaluations/validate_multisource.py) usa o SDK oficial por `stdio`, confere a descoberta das dez ferramentas e o contrato do núcleo, consulta os caches individualmente e em grupos e reconstrói originais selecionados com SHA-256. `--exercise-online` revalida OWASP e o grupo CVE/KEV/NVD. `--exercise-memory` cria, consulta e exclui uma nota descartável apoiada em OWASP/ATT&CK/CWE.

```powershell
.\.venv\Scripts\python.exe .\evaluations\validate_multisource.py --data-dir .\data --report .\.local-data\mcp-multisource-validation-report.json --skip malapi --exercise-memory --exercise-online
```

O segundo comando pressupõe que `data/` contenha o snapshot preparado e as amostras dos caches multifontes; o primeiro comando, com diretório isolado, não preenche `data/`. Se necessário, execute também o ensaio por URL apontando para `--data-dir .\data` antes do MCP. Reinicie um núcleo antigo após atualizar o código. Os modos online acessam as origens e gravam cache; os relatórios registram a seleção, não a aprovação de todo o acervo ou das respostas de GPT/Claude.

`--skip malapi` registra uma exclusão explícita por indisponibilidade observada, não uma aprovação.

## Validação multifontes — 21/10/2026

A suíte completa passou com **681 testes, zero falhas e zero skips**, incluindo o modelo semântico real. As 36 novas fontes disponíveis passaram por coleta individual, reutilização e regressão offline das anteriores. O ensaio pelo SDK oficial MCP validou **37 fontes com evidências**, contando a OWASP existente, e descobriu as dez ferramentas no contrato 3. Todas as amostras retornadas estavam `current` segundo a política de validade do cache. Isso não comprova cobertura integral dos repositórios.

Foram verificadas consultas combinadas, revalidação online OWASP/CVE/KEV/NVD, reconstrução dos bytes originais selecionados e gravação/consulta/exclusão de uma nota descartável. A indisponibilidade do MalAPI foi reconfirmada no núcleo principal sem afetar a consulta OWASP. Os 24 pré-requisitos de recuperação do snapshot passaram; seis casos de cliente/ambiente continuam sem execução. O snapshot de 1.774 documentos foi preservado, com os novos caches locais separados. O Codex conectado confirmou contrato 3 e 38 fontes cadastradas; a descoberta das ferramentas novas no cliente exige recarregar a conexão.

Ruff, verificação do lock offline e compatibilidade dos pacotes instalados passaram. A auditoria OSV de 100 dependências aplicáveis não encontrou vulnerabilidades conhecidas nem pulou pacotes. Os três arquivos `requirements*.lock` foram regenerados. Foram corrigidos, entre outros casos, mistura de estados entre fontes, JSON persistido inválido, migração de configuração por registro, confusão de SQL/NoSQL e download redundante de originais GitHub imutáveis. A publicação atômica do piloto ganhou tentativas limitadas para bloqueios breves do Windows; uma recusa persistente mantém o diretório sem publicação.

Relatórios reproduzíveis: [resumo e limitações](../evaluations/results/2026-10-21-multisource-summary.json), [gates individuais iniciais](../evaluations/results/2026-10-21-initial-source-gates.json), [regressão por URL/cache](../evaluations/results/2026-10-21-source-urls.json), [MCP real](../evaluations/results/2026-10-21-mcp-multisource.json) e [recuperação do snapshot](../evaluations/results/2026-10-21-retrieval-multisource.json).

O Lírio foi usado para contexto e registro das decisões no Graphify. As duas tentativas de revisão desta expansão via OpenRouter falharam com `OPENROUTER_RESPONSE`; não houve aprovação externa dessa revisão. Os resultados acima são dos testes locais. A fidelidade das respostas GPT/Claude e o aplicativo Claude continuam sem homologação nesta etapa.

## Histórico da primeira extensão OWASP — 21/10/2026

Os resultados desta seção pertencem à entrega anterior de OWASP e memória; não são a contagem de testes nem a cobertura da expansão multifontes. A suíte geral daquela etapa passou com **216 testes, zero falhas e zero skips**, incluindo dois testes semânticos reais offline. Após os ajustes de compatibilidade do núcleo, passaram mais **53 testes focados** de runtime/MCP/pesquisa; após acrescentar a referência à leitura paginada, os **17 testes de pesquisa** passaram novamente. Esses números representam rodadas sobrepostas, não uma soma de testes distintos. Ruff e `git diff --check` passaram naquela rodada.

Pelo SDK oficial MCP, usando `stdio` e o núcleo autenticado real, foram descobertas as dez ferramentas e validados: coleta OWASP, reutilização sem novo download, leitura exata em três páginas, memória explícita, consulta offline e exclusão da nota de teste. O catálogo observado continha 137 caminhos; apenas a cheat sheet de senhas entrou no cache desse ensaio (20.550 bytes). O snapshot semântico permaneceu `8c3f327f9674490ba2ac1a9e521071cf`, com 1.774 documentos. Os 24 pré-requisitos de recuperação foram repetidos e passaram; seis casos de cliente/ambiente continuam pendentes. Consulte o [relatório sanitizado](../evaluations/results/2026-10-21-ondemand-mcp.json).

Nessa primeira etapa, o Lírio revisou o desenho via OpenRouter, conforme autorização, e apontou riscos de concorrência, frescor, contrato e invalidação. A revisão foi textual; não executou testes. As correções foram verificadas localmente. Isso não registra uma revisão concluída da expansão multifontes. O SDK confirma o protocolo, não as respostas de GPT/Claude: as 30 respostas e a homologação do aplicativo Claude continuam pendentes. O Codex conectado confirmou o núcleo daquela entrega e o snapshot; atualizações posteriores exigem novo reinício e descoberta de ferramentas.

## Implementado

| Parte | Estado |
|---|---|
| Fontes | Piloto de cinco fontes com commits e hashes fixados; parser NVD para importação local. Consulta por URLs e cache separado para os adaptadores anunciados no catálogo. |
| Corpus piloto preservado | 1.774 documentos, 1.949 trechos, 1.757 entidades; 1.754 entradas KEV; zero quarentena. Contagens não incluem caches nem notas. |
| Índice semântico preparado | 2.715 vetores locais, 384 dimensões, snapshot `8c3f327f9674490ba2ac1a9e521071cf`. |
| Recuperação | Snapshot: IDs exatos, BM25, filtros, E5 multilingual local, Qdrant local e fusão RRF. Caches e memória: recuperação lexical em camadas separadas. |
| Originais | Bytes preservados, hashes, paginação, visualização UTF-8 e referência ao arquivo de origem dos objetos extraídos. |
| PDFs selecionados | Texto derivado por `pypdf` em processo com limites; sem OCR, renderização ou execução. Original binário e hash preservados. |
| Atualizações | Publicação atômica de snapshots; caches incrementais por fonte, com falhas, revisões e verificação explícitas. Uma falha de fonte não elimina as demais. |
| MCP | Dez ferramentas pelo SDK oficial; cinco consultas originais somente leitura e cinco operações de catálogo/pesquisa/cache/memória com efeitos declarados. Adaptadores stdio compartilham o núcleo. Para continuidade entre aplicativos no Windows, iniciar o núcleo manualmente com `--keep-alive`. |
| Memória | Notas derivadas, referências obrigatórias, validade, quotas, deduplicação e exclusão por ID. |
| Núcleo | Loopback autenticado por HMAC, proteção contra replay, permissões privadas e limites de conexão/fila. |
| Administração | CLI para importar, baixar piloto, preparar modelo, consultar, pesquisar sob demanda, inspecionar catálogo, avaliar e gerar configurações. |
| Distribuição | Projeto Python, wheel local, `uv.lock` e requisitos exportados com hashes; corpus e pesos fora do pacote. |

## Histórico de validação da implementação inicial

- **105 testes passaram na suíte geral**, com os dois testes semânticos explicitamente separados nessa rodada. Incluem autenticação, recusa de conexões e manutenção do núcleo manual além do limite de inatividade.
- **Dois testes semânticos reais passaram**, sem tentativas de rede, usando E5 de 384 dimensões e Qdrant. Verificam normalização, limite de 512 tokens, recuperação sem correspondência lexical, reconstrução, acesso à geração anterior e preservação do ativo após falha.
- **Dez checks sintéticos** passaram dentro dos testes de avaliação, incluindo reconstrução dos bytes.
- **Onze checks do piloto real** passaram tanto no perfil lexical quanto no semântico. O gabarito verifica os commits das fontes, sem depender de um UUID de máquina específico. A consulta em português sobre armazenamento de senhas recuperou a orientação correspondente da OWASP em primeiro lugar.
- Integração completa pelo cliente do SDK: inicialização, descoberta de cinco ferramentas, stdio, núcleo autenticado, base real, consulta exata, busca, relações e integridade do original.
- Inicialização semântica validada no caminho de produção: CLI `core --keep-alive` em processo independente e CLI `serve` como adaptador do SDK. Em uma base isolada de dois documentos sintéticos, com E5 real e offline, o núcleo iniciou em 0,851 s, a primeira busca levou 26,932 s e a seguinte 0,050 s. O núcleo sobreviveu ao fechamento do adaptador; todos os processos criados nesse ensaio foram encerrados. Esses tempos não são um benchmark do corpus completo.
- Ruff aprovado e `pip check` sem dependências quebradas.
- Auditoria dos requisitos fixados dos perfis básico, semântico e de desenvolvimento pelo `pip-audit`/OSV: **nenhuma vulnerabilidade conhecida encontrada** na consulta realizada. Isso não é garantia de ausência de vulnerabilidades.
- Wheel gerado e inspecionado: somente código do pacote e metadados; sem corpus, modelos ou credenciais.

O modelo utilizado é `intfloat/multilingual-e5-small`, revisão `614241f622f53c4eeff9890bdc4f31cfecc418b3`. O uso é em CPU, com até quatro threads. Os testes de vetores não constituem medição de Recall@k, precisão das respostas ou resistência completa a prompt injection.

## Histórico de uso nesta cópia

Na validação pelo Codex em 21/10/2026, o estado da base respondeu, mas a primeira busca semântica excedeu o prazo e a tentativa seguinte recebeu `BUSY`. A carga continuou no núcleo; uma nova consulta, depois de carregado, retornou em aproximadamente 0,5 s. Foi acrescentado `core --keep-alive --warmup`: a preparação do modelo e do índice ocorre antes de anunciar prontidão e aceitar consultas. Após reiniciar com essa opção, a mesma busca pelo MCP do Codex retornou em aproximadamente 2,5 s; a leitura do documento original da OWASP também retornou conteúdo e citação. O estado `partial` dessas respostas indica paginação, não timeout. Naquela rodada, a suíte passou com **110 testes**, com os dois testes semânticos optativos separados; a busca semântica real foi verificada diretamente pelo MCP conectado.

Os comandos estão no [README](../README.md). A base real fica em `data/`; as configurações geradas, em `data/client-config/codex.toml` e `data/client-config/claude.json`. O Codex foi conectado e consultou a base nesta máquina; a conexão no aplicativo Claude ainda não foi homologada. A base sintética dos testes permanece separada.

A etapa seguinte acrescentou seleção de trechos com conteúdo, contexto adjacente curto e uma matriz de pré-requisitos de recuperação para as 30 perguntas. Resultados, comparação anterior/posterior e pendências estão em [Validação de recuperação — 21/10/2026](VALIDACAO_RECUPERACAO_2026-10-21.md).

Os relatórios locais ficam em `data/evaluation-pilot.json`, `data/evaluation-pilot-semantic-final.json`, `.local-data/pytest-final.xml`, `.local-data/mcp-semantic-production.json`, `.local-data/audit-semantic.json` e `.local-data/audit-all.json`. A primeira rodada semântica falhou em uma consulta por causa do prazo de carga inicial de 45 segundos; esse prazo foi ajustado para 120 segundos no núcleo e 150 segundos na configuração gerada para Codex. O relatório inicial foi mantido em `data/evaluation-pilot-semantic.json`. Um teste intermediário que colocava adaptador e núcleo no mesmo processo bloqueou ao importar NumPy; o ensaio final usou os processos separados previstos na arquitetura e passou. Dados locais e relatórios de execução estão ignorados para publicação. O histórico dos commits e a atribuição das fontes estão em [ORIGENS.md](ORIGENS.md).

## Trabalho seguinte

1. Homologar a instalação e as respostas nas interfaces reais de Codex e Claude.
2. Revisar gabaritos das trinta perguntas de aceitação e medir recuperação e fidelidade das respostas.
3. Ampliar a cobertura exercitada dos adaptadores e medir tempo, memória e disco antes de recomendar grandes volumes; tratar separadamente fontes com acesso ou licenciamento pendente.
4. Acrescentar retenção de snapshots e instalação mais simples; avaliar reranker com evidência de ganho.
5. Validar a instalação em um clone novo do repositório público.

O código é publicado em [mcp-server-cybersecurity](https://github.com/joaquimmoraesgabriel-cmyk/mcp-server-cybersecurity), preservando o commit inicial e sua licença MIT. Dados locais, pesos e credenciais ficam fora do repositório. O [guia de conexão](CONECTAR_CODEX.md) descreve a configuração manual e o roteiro de validação no Codex. A compatibilidade inicial é para clientes GPT via Codex e Claude; o protocolo não atesta qual modelo está por trás do cliente.
