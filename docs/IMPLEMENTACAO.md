# Entrega da primeira implementação

Alfa local `0.1.0a1`, desenvolvida e validada no Windows com Python 3.12.14. Este documento descreve o que foi executado; a [especificação](ESPECIFICACAO_RAG_MCP.md) continua sendo o alvo mais amplo.

## Implementado

| Parte | Estado |
|---|---|
| Fontes | Cinco fontes oficiais baixadas com commits e hashes fixados; parser NVD adicional para importação local. |
| Corpus piloto | 1.774 documentos, 1.949 trechos, 1.757 entidades; 1.754 entradas KEV; zero quarentena. |
| Índice semântico preparado | 2.715 vetores locais, 384 dimensões, snapshot `8c3f327f9674490ba2ac1a9e521071cf`. |
| Recuperação | IDs exatos, BM25, filtros, E5 multilingual local, Qdrant local e fusão RRF. |
| Originais | Bytes preservados, hashes, paginação, visualização UTF-8 e referência ao arquivo de origem dos objetos extraídos. |
| Atualizações | Publicação atômica de snapshots; falha de preparação mantém a geração anterior. |
| MCP | Cinco ferramentas somente leitura pelo SDK oficial; adaptadores stdio compartilham o núcleo. Para continuidade entre aplicativos no Windows, iniciar o núcleo manualmente com `--keep-alive`. |
| Núcleo | Loopback autenticado por HMAC, proteção contra replay, permissões privadas e limites de conexão/fila. |
| Administração | CLI para importar, baixar piloto, preparar modelo, consultar, avaliar e gerar configurações. |
| Distribuição | Projeto Python, wheel local, `uv.lock` e requisitos exportados com hashes; corpus e pesos fora do pacote. |

## Validação executada

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

## Usar nesta cópia

Os comandos estão no [README](../README.md). A base real fica em `data/`; as configurações prontas, em `data/client-config/codex.toml` e `data/client-config/claude.json`. Esses arquivos não foram aplicados aos aplicativos. A base sintética dos testes permanece separada.

Os relatórios locais ficam em `data/evaluation-pilot.json`, `data/evaluation-pilot-semantic-final.json`, `.local-data/pytest-final.xml`, `.local-data/mcp-semantic-production.json`, `.local-data/audit-semantic.json` e `.local-data/audit-all.json`. A primeira rodada semântica falhou em uma consulta por causa do prazo de carga inicial de 45 segundos; esse prazo foi ajustado para 120 segundos no núcleo e 150 segundos na configuração gerada para Codex. O relatório inicial foi mantido em `data/evaluation-pilot-semantic.json`. Um teste intermediário que colocava adaptador e núcleo no mesmo processo bloqueou ao importar NumPy; o ensaio final usou os processos separados previstos na arquitetura e passou. Dados locais e relatórios de execução estão ignorados para publicação. O histórico dos commits e a atribuição das fontes estão em [ORIGENS.md](ORIGENS.md).

## Trabalho seguinte

1. Homologar a instalação e as respostas nas interfaces reais de Codex e Claude.
2. Revisar gabaritos das trinta perguntas de aceitação e medir recuperação e fidelidade das respostas.
3. Ampliar o corpus, medir tempo/memória e otimizar a indexação antes de recomendar grandes volumes.
4. Acrescentar retenção de snapshots e instalação mais simples; avaliar reranker com evidência de ganho.
5. Validar a instalação em um clone novo do repositório público.

O código é publicado em [mcp-server-cybersecurity](https://github.com/joaquimmoraesgabriel-cmyk/mcp-server-cybersecurity), preservando o commit inicial e sua licença MIT. Dados locais, pesos e credenciais ficam fora do repositório. O [guia de conexão](CONECTAR_CODEX.md) descreve a configuração manual e o roteiro de validação no Codex. A compatibilidade inicial é para clientes GPT via Codex e Claude; o protocolo não atesta qual modelo está por trás do cliente.
