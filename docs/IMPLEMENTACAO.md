# Implementação local e extensão sob demanda

Alfa local `0.1.0a1`, desenvolvida e validada no Windows com Python 3.12.14. Este documento descreve o que foi executado; a [especificação](ESPECIFICACAO_RAG_MCP.md) continua sendo o alvo mais amplo.

## Extensão de 21/10/2026

A implementação agora preserva o snapshot semântico e acrescenta cache OWASP sob demanda e memória derivada, descritos em [Pesquisa sob demanda](PESQUISA_SOB_DEMANDA.md). São dez ferramentas: as cinco consultas originais, `knowledge_catalog`, `knowledge_research`, `knowledge_get_cached_document`, `knowledge_remember` e `knowledge_forget`.

A descoberta OWASP usa uma listagem de caminhos no commit observado e correspondência local de nomes/aliases. O conteúdo coletado usa SQLite/FTS5 em cache separado; o índice E5/Qdrant existente não é reconstruído por pergunta. `auto`, `refresh` e `offline` controlam a rede; TTL, falhas, revisões, limites e datas ficam visíveis. ATT&CK, Sigma, CVE e KEV continuam no snapshot local.

A memória recebe somente notas explicitamente submetidas com referências verificáveis. Todas são `derived_unverified`, têm prazo e limites, e são omitidas quando suas evidências deixam de ser atuais. Ela não captura conversas nem treina modelos. Clientes que usam o mesmo diretório de dados compartilham as notas.

A espera de rede usa trava separada da consulta vetorial. Os endpoints permanecem locais e autenticados; não foram acrescentadas ferramentas de shell, scanner, execução de documentos ou administração dos snapshots. O núcleo anuncia `tool_contract: 2`; atualizar uma instalação exige reiniciar o núcleo e redescobrir as ferramentas no cliente, sem reimportar a base.

**Validação integrada concluída no escopo abaixo.** A suíte geral passou com **216 testes, zero falhas e zero skips**, incluindo dois testes semânticos reais offline. Após os ajustes finais de compatibilidade do núcleo, passaram mais **53 testes focados** de runtime/MCP/pesquisa; após acrescentar a referência à leitura paginada, os **17 testes de pesquisa** passaram novamente. Esses números representam rodadas sobrepostas, não uma soma de testes distintos. Ruff e `git diff --check` passaram.

Pelo SDK oficial MCP, usando `stdio` e o núcleo autenticado real, foram descobertas as dez ferramentas e validados: coleta OWASP, reutilização sem novo download, leitura exata em três páginas, memória explícita, consulta offline e exclusão da nota de teste. O catálogo observado continha 137 caminhos; apenas a cheat sheet de senhas entrou no cache desse ensaio (20.550 bytes). O snapshot semântico permaneceu `8c3f327f9674490ba2ac1a9e521071cf`, com 1.774 documentos. Os 24 pré-requisitos de recuperação foram repetidos e passaram; seis casos de cliente/ambiente continuam pendentes. Consulte o [relatório sanitizado](../evaluations/results/2026-10-21-ondemand-mcp.json).

O Lírio revisou o desenho via OpenRouter, conforme autorização, e apontou riscos de concorrência, frescor, contrato e invalidação. A revisão foi textual; não executou testes. As correções foram verificadas localmente. O SDK confirma o protocolo, não as respostas de GPT/Claude: as 30 respostas e a homologação do aplicativo Claude continuam pendentes. O Codex conectado confirmou o núcleo novo e o snapshot; esta conexão ainda precisa redescobrir as ferramentas novas.

## Implementado

| Parte | Estado |
|---|---|
| Fontes | Cinco fontes oficiais baixadas com commits e hashes fixados; parser NVD adicional para importação local. |
| Corpus piloto | 1.774 documentos, 1.949 trechos, 1.757 entidades; 1.754 entradas KEV; zero quarentena. |
| Índice semântico preparado | 2.715 vetores locais, 384 dimensões, snapshot `8c3f327f9674490ba2ac1a9e521071cf`. |
| Recuperação | IDs exatos, BM25, filtros, E5 multilingual local, Qdrant local e fusão RRF. |
| Originais | Bytes preservados, hashes, paginação, visualização UTF-8 e referência ao arquivo de origem dos objetos extraídos. |
| Atualizações | Publicação atômica de snapshots; cache OWASP incremental separado, com falhas e verificação explícitas. |
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

Na validação pelo Codex em 21/10/2026, o estado da base respondeu, mas a primeira busca semântica excedeu o prazo e a tentativa seguinte recebeu `BUSY`. A carga continuou no núcleo; uma nova consulta, depois de carregado, retornou em aproximadamente 0,5 s. Foi acrescentado `core --keep-alive --warmup`: a preparação do modelo e do índice ocorre antes de anunciar prontidão e aceitar consultas. Após reiniciar com essa opção, a mesma busca pelo MCP do Codex retornou em aproximadamente 2,5 s; a leitura do documento original da OWASP também retornou conteúdo e citação. O estado `partial` dessas respostas indica paginação, não timeout. A suíte atual passou com **110 testes**, com os dois testes semânticos optativos separados; a busca semântica real foi verificada diretamente pelo MCP conectado.

Os comandos estão no [README](../README.md). A base real fica em `data/`; as configurações geradas, em `data/client-config/codex.toml` e `data/client-config/claude.json`. O Codex foi conectado e consultou a base nesta máquina; a conexão no aplicativo Claude ainda não foi homologada. A base sintética dos testes permanece separada.

A etapa seguinte acrescentou seleção de trechos com conteúdo, contexto adjacente curto e uma matriz de pré-requisitos de recuperação para as 30 perguntas. Resultados, comparação anterior/posterior e pendências estão em [Validação de recuperação — 21/10/2026](VALIDACAO_RECUPERACAO_2026-10-21.md).

Os relatórios locais ficam em `data/evaluation-pilot.json`, `data/evaluation-pilot-semantic-final.json`, `.local-data/pytest-final.xml`, `.local-data/mcp-semantic-production.json`, `.local-data/audit-semantic.json` e `.local-data/audit-all.json`. A primeira rodada semântica falhou em uma consulta por causa do prazo de carga inicial de 45 segundos; esse prazo foi ajustado para 120 segundos no núcleo e 150 segundos na configuração gerada para Codex. O relatório inicial foi mantido em `data/evaluation-pilot-semantic.json`. Um teste intermediário que colocava adaptador e núcleo no mesmo processo bloqueou ao importar NumPy; o ensaio final usou os processos separados previstos na arquitetura e passou. Dados locais e relatórios de execução estão ignorados para publicação. O histórico dos commits e a atribuição das fontes estão em [ORIGENS.md](ORIGENS.md).

## Trabalho seguinte

1. Homologar a instalação e as respostas nas interfaces reais de Codex e Claude.
2. Revisar gabaritos das trinta perguntas de aceitação e medir recuperação e fidelidade das respostas.
3. Validar a extensão sob demanda e ampliar adaptadores de fonte, medindo tempo/memória antes de recomendar grandes volumes.
4. Acrescentar retenção de snapshots e instalação mais simples; avaliar reranker com evidência de ganho.
5. Validar a instalação em um clone novo do repositório público.

O código é publicado em [mcp-server-cybersecurity](https://github.com/joaquimmoraesgabriel-cmyk/mcp-server-cybersecurity), preservando o commit inicial e sua licença MIT. Dados locais, pesos e credenciais ficam fora do repositório. O [guia de conexão](CONECTAR_CODEX.md) descreve a configuração manual e o roteiro de validação no Codex. A compatibilidade inicial é para clientes GPT via Codex e Claude; o protocolo não atesta qual modelo está por trás do cliente.
