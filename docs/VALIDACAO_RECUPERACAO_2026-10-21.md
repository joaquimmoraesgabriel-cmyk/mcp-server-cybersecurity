# Validação de recuperação — 21/10/2026

O núcleo local foi atualizado, mantendo o snapshot `8c3f327f9674490ba2ac1a9e521071cf`, os 1.774 documentos e o perfil semântico. Esta etapa melhora os trechos entregues e materializa pré-requisitos de recuperação para as 30 perguntas. Não homologa as 30 respostas finais do GPT ou Claude.

## Resultados medidos

| Rodada | Casos executados | Passaram | Falharam | Pendentes |
| --- | ---: | ---: | ---: | ---: |
| Desenvolvimento antes da mudança | 15 | 13 | 2 | 0 |
| Desenvolvimento após a mudança | 15 | 15 | 0 | 0 |
| Pré-requisitos do conjunto de aceitação | 9 | 9 | 0 | 6 |
| Matriz completa de recuperação | 24 | 24 | 0 | 6 |
| Regressão do piloto anterior | 11 | 11 | 0 | 0 |

Os dois casos que falharam inicialmente foram **Q12 — SQL Injection** e **Q14 — armazenamento de senhas**. Ambos encontravam o documento esperado, mas não entregavam nos trechos o conteúdo exigido pelo gabarito.

Os relatórios sem conteúdo de fontes ou credenciais estão em [desenvolvimento antes](../evaluations/results/2026-10-21-development-before.json) e [matriz final](../evaluations/results/2026-10-21-retrieval-final.json). Eles registram snapshot, revisões, hash do benchmark, hash do runner, resultados e tempos por caso. As medições usam o núcleo preparado; os tempos não incluem inicialização ou geração de respostas de LLM.

Os arquivos originais da rodada usaram CRLF no Windows; o repositório normaliza para LF. O hash de bytes foi preservado nos relatórios históricos. Foi acrescentado `benchmark_content_sha256`, calculado sobre o mesmo JSON normalizado, para comparar o gabarito publicado com o usado nas duas rodadas, independentemente dos finais de linha.

O benchmark de recuperação foi fixado antes das medições. A busca foi ajustada usando apenas desenvolvimento; os nove casos executáveis de aceitação foram consultados depois da última alteração. A rodada completa repetiu esses checks para produzir um único relatório. As perguntas de aceitação constam da especificação pública e não constituem um teste cego externo.

## O que mudou

1. **Preparação do núcleo:** `core --keep-alive --warmup` carrega e exercita modelo/índice antes de anunciar prontidão. A correção foi publicada no commit `af52be4`. O tempo de carga ainda depende da máquina; é necessário esperar a mensagem `Pronto`.
2. **Trechos com conteúdo:** cabeçalhos Markdown isolados deixam de ocupar posições de evidência. O ranking do documento continua baseado nos canais de recuperação existentes.
3. **Aproveitamento do orçamento:** até quatro trechos por documento, cada um com até 1.800 caracteres, somando no máximo 3.600. O limite total de conteúdo da resposta permanece em vigor.
4. **Contexto adjacente:** se o primeiro trecho Markdown e a seção imediatamente seguinte cabem juntos em 1.800 caracteres, a seção seguinte é incluída como `adjacent_context`, com seu próprio ID e citação. Não há expansão recursiva nem duplicação de seções.
5. **Avaliação verificável:** casos com múltiplos checks, campos específicos por fonte, documentos/posições/termos esperados, reconstrução de originais paginados, ausência de relação em todas as páginas e execução separada por conjunto.

A remoção de títulos vazios resolveu Q14. Apenas ampliar a quantidade de trechos curtos ainda deixou Q12 sem a defesa principal. O contexto adjacente resolveu esse caso: o trecho que descreve uma consulta insegura passou a vir acompanhado da seção **Primary Defenses**, que inclui consultas parametrizadas. Nenhum gabarito foi afrouxado para aprovar essas tentativas.

Os originais, hashes, IDs e snapshot foram preservados; não foi necessário baixar novamente o acervo ou recalcular embeddings. A seleção de contexto é uma heurística limitada, não um reranker treinado nem garantia geral de relevância.

## Testes e validação no Codex

- **127 testes passaram**, sem skips na rodada final, incluindo os dois testes semânticos com E5 real. A suíte levou 70,99 segundos. Os testes semânticos usam base temporária e bloqueiam conexões externas durante sua execução.
- Ruff e `git diff --check` passaram.
- Depois da publicação inicial, um teste adicional confirmou a comparação dos hashes de conteúdo entre LF/CRLF; a suíte focada do avaliador foi repetida. Essa alteração afeta somente metadados do relatório.
- Pelo MCP conectado ao Codex, a consulta sobre senhas retornou o documento Password Storage com conteúdo de introdução, parâmetros e outras seções; a consulta de SQL Injection retornou a seção de defesas com citação própria. Ambas conservaram o snapshot acima. `partial` indicou que havia mais resultados disponíveis por paginação.
- O núcleo atualizado ficou ativo com `--keep-alive --warmup`. A reinicialização expira cursores antigos; consultas novas usam o mesmo acervo.

O teste de integração não equivale a uma campanha completa de avaliação das respostas do GPT. O aplicativo Claude ainda não foi homologado.

## Pendências explícitas

| Caso | Trabalho necessário |
| --- | --- |
| Q21 | Duas variantes de tempo controladas e avaliação da resposta sobre presença no KEV “hoje”. |
| Q22 | Avaliar se o cliente distingue ausência no KEV de ausência de exploração. |
| Q27 | Criar e usar fixture isolado de divergência entre CVE e NVD. |
| Q28 | Avaliar resposta sem telemetria; não diagnosticar a máquina a partir do acervo. |
| Q29 | Criar fixture adversarial e observar comportamento do cliente isolado. |
| Q30 | Observar cliente expondo somente as cinco ferramentas e verificar que não alega execução de scanner. |

Mesmo nos outros 24 casos, o sucesso é de **entrega e preservação de evidências**. A fidelidade das explicações, a qualidade de cada citação no texto final e a obediência aos limites precisam ser avaliadas separadamente nos clientes. Não há declaração de Recall@10, 95% de fidelidade, resistência comprovada a prompt injection ou aprovação para release final.

O próximo marco é preparar esses cenários isolados e registrar respostas/ações de Codex e Claude com versões identificadas, antes de ampliar o corpus. Expansão de fontes, instalação limpa em outra máquina e empacotamento público continuam etapas seguintes.

## Uso do Lírio

O projeto foi vinculado ao Lírio e seu mapa Graphify foi consultado para recuperar estrutura e decisões. Os resultados desta etapa foram registrados na memória do projeto.

Após autorização explícita do usuário para o envio de código/testes/documentação via OpenRouter, a revisão por outra IA foi solicitada na execução `80a69e18-b245-4705-bd9f-a8954f85d009`. Ela falhou com `OPENROUTER_NETWORK`, antes da seleção de um modelo. Portanto, **não houve parecer de uma segunda IA pelo Lírio**. A implementação, revisão e verificações desta entrega foram realizadas no Codex.
