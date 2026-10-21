# Cyber RAG MCP — evidências locais e pesquisa sob demanda

Servidor MCP local para consultar evidências de cibersegurança. A IA recebe trechos e fontes verificáveis; o aplicativo cliente produz a resposta. Versão **0.1.0a1**, em desenvolvimento.

O servidor combina o snapshot local já preparado, um cache de fontes obtidas sob demanda e uma memória separada de notas derivadas. A coleta sob demanda começa pela **OWASP Cheat Sheet Series**; ATT&CK, Sigma, CVE e KEV continuam consultados pelo snapshot. Veja o [fluxo, as garantias e os limites](docs/PESQUISA_SOB_DEMANDA.md).

O ambiente, o piloto e o modelo são preparados localmente com os comandos abaixo. Veja a [entrega e os resultados](docs/IMPLEMENTACAO.md) e o [guia para conectar e validar no Codex](docs/CONECTAR_CODEX.md). Na máquina de desenvolvimento original, `.venv/`, `data/` e os blocos em `data/client-config/` já estão preparados; essas pastas não acompanham o clone do repositório.

O projeto roda no computador de quem instala. A compatibilidade pretendida nesta etapa é **Codex, para modelos GPT, e Claude Desktop/Claude Code**, por MCP `stdio`. Não há autenticação da marca do modelo: qualquer cliente que execute o programa com acesso local pode falar MCP. O ChatGPT na web não acessa diretamente este processo `stdio`.

## O que já existe

- Dez ferramentas MCP: cinco consultas ao snapshot, catálogo de fontes, pesquisa conjunta, leitura do cache e gravação/exclusão explícitas de notas.
- Importação de ATT&CK STIX 2.1, OWASP Markdown, Sigma YAML, CVE JSON 5 e KEV. NVD 2.0 pode ser importado de arquivos locais.
- Piloto oficial com commits fixados: duas técnicas ATT&CK, cinco cheat sheets, uma regra Sigma, CVE-2021-44228 e catálogo KEV completo no commit selecionado. É uma seleção inicial, não a cobertura completa planejada.
- SQLite com busca exata e BM25. Perfil semântico opcional: E5 multilingual local e Qdrant local, fusão RRF. Sem reranker nesta versão.
- Snapshots imutáveis, troca atômica do índice ativo, citações e originais com SHA-256. Arquivos grandes são paginados em base64 sem alterar BOM ou finais de linha.
- Um núcleo local compartilhado entre clientes, com comunicação autenticada em loopback. A pesquisa pode consultar a OWASP e persistir evidências; o MCP não expõe shell, scanner nem administração dos snapshots.
- Catálogo OWASP por revisão, descoberta local por nomes de arquivos e aliases, cache incremental com SHA-256 e verificação condicional. O conteúdo novo usa busca lexical; o snapshot semântico existente permanece separado.
- Memória local com referências obrigatórias, prazo de validade e invalidação quando a evidência muda. Notas são sempre `derived_unverified`; não treinam o modelo nem capturam automaticamente a conversa.

## Preparar o ambiente

Requer Python 3.11–3.13 e [uv](https://docs.astral.sh/uv/getting-started/installation/). Os exemplos seguintes usam PowerShell na pasta do projeto.

```powershell
uv sync --locked --no-install-project
# Executar diretamente o código local; nenhuma instalação global.
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
.\.venv\Scripts\python.exe -m cyber_rag doctor --data-dir .\data
```

A instalação bloqueia builds de dependências a partir de código-fonte. O lockfile fixa versões; o extra semântico é instalado apenas quando solicitado. O ambiente local criado durante o desenvolvimento fica em `.venv` e não deve ir ao GitHub.

Alternativa com pip, para o perfil básico: `python -m pip install --require-hashes --only-binary=:all: -r requirements.lock`, dentro de um ambiente virtual. `requirements-dev.lock` inclui os testes; `requirements-semantic.lock` inclui os embeddings. Esses arquivos são exportados do `uv.lock` e devem ser regenerados juntos ao atualizar dependências.

## Criar a base com fontes reais

```powershell
.\.venv\Scripts\python.exe -m cyber_rag sync-pilot --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag status --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag search 'PowerShell' --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag search 'SQL injection' --source owasp --data-dir .\data
```

`sync-pilot` acessa a rede para baixar a seleção cadastrada. O manifesto registra hashes, commits, licenças e o escopo. Erros de parsing ou quarentena impedem publicar a nova geração. As cinco consultas ao snapshot funcionam sem rede. Executar novamente o comando cria outra geração; não há agendamento automático. `knowledge_research` usa um cache separado e pode buscar arquivos OWASP sob demanda, sem reconstruir essa geração.

Também é possível importar um manifesto local:

```powershell
.\.venv\Scripts\python.exe -m cyber_rag import .\caminho\manifest.json --data-dir .\data
```

O manifesto representa **toda a seleção da próxima geração**. Não faz merge implícito com a anterior. Os diretórios de fonte devem estar dentro da pasta do manifesto. Use `tests/fixtures/sources.json` como referência estrutural, mas não misture dados sintéticos à base real.

## Pesquisar nas fontes e na memória

```powershell
.\.venv\Scripts\python.exe -m cyber_rag catalog --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'armazenamento de senhas' --source owasp --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'password storage' --source owasp --freshness refresh --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'password storage' --source owasp --freshness offline --data-dir .\data
```

`auto` reutiliza o catálogo verificado por até 24 horas; `refresh` solicita uma nova verificação, respeitando bloqueios temporários após falhas; `offline` não faz requisições externas. A pesquisa mantém `layers.snapshot`, `layers.source_cache` e `layers.memory` separados, com datas e falhas próprias. Consulta ao GitHub não equivale a verificar a correção factual de um documento.

O primeiro acesso consulta os nomes de arquivos em `cheatsheets/` no commit observado e baixa até três arquivos selecionados. A pergunta não é enviada ao GitHub: a descoberta por caminho e a busca no cache acontecem localmente. Um caminho conhecido pode ser indicado com `--path cheatsheets/Password_Storage_Cheat_Sheet.md`. Não são aceitas URLs livres.

Para atualizar uma instalação existente, reinicie o núcleo e recarregue a conexão MCP no cliente para descobrir as dez ferramentas. Não é necessário reimportar o piloto nem baixar novamente o modelo. Um núcleo antigo retorna `CORE_UPGRADE_REQUIRED` nas novas operações; siga o [guia de atualização e validação](docs/CONECTAR_CODEX.md).

## Ativar busca semântica

```powershell
uv sync --locked --extra semantic --no-install-project
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
.\.venv\Scripts\python.exe -m cyber_rag models prepare --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag sync-pilot --profile semantic --data-dir .\data
```

`models prepare` baixa `intfloat/multilingual-e5-small` e fixa a revisão. O modelo usa CPU e 384 dimensões. A consulta carrega somente pesos locais, sem código remoto. É necessário reindexar ao mudar de perfil. O perfil lexical continua útil para IDs, termos técnicos e regras; não é anunciado como busca semântica. Há uma pequena tabela explícita de termos português→inglês, não tradução completa.

A inferência utiliza até quatro threads de CPU. A primeira importação das bibliotecas pode ser lenta no Windows; o estado da geração anterior permanece válido durante a preparação. Datas upstream que contêm somente o dia são comparadas a partir de 00:00 UTC; timestamps upstream sem fuso são interpretados como UTC, preservando o valor original nos metadados.

O núcleo admite até 120 segundos de espera de resposta para acomodar a primeira carga do modelo; a configuração gerada para Codex usa 150 segundos por ferramenta. Clientes com um prazo próprio mais curto podem exigir ajuste. Depois de carregado, o modelo é reutilizado pelo núcleo. Isso não é uma promessa de latência para qualquer máquina.

## Conectar os clientes

O comando abaixo imprime um bloco de configuração; não edita os aplicativos:

```powershell
.\.venv\Scripts\python.exe -m cyber_rag config --client codex --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag config --client claude --data-dir .\data
```

Copie o bloco para a configuração MCP do cliente correspondente. A configuração usa caminhos absolutos para o Python e a base. No desenvolvimento, inclui `PYTHONPATH` apontando para `src`; mantenha a pasta do projeto no mesmo lugar. Para Claude Code, use os mesmos `command`, `args` e `env` em sua configuração MCP.

O cliente inicia `python -m cyber_rag serve`. Esse adaptador inicia ou reutiliza o núcleo local. Dois clientes com o mesmo `--data-dir` compartilham esse núcleo. No modo automático, ele encerra após quinze minutos sem consultas e reinicia na próxima chamada. Credenciais ficam em `data/runtime` com permissões privadas; não são impressas.

**Para usar Codex e Claude simultaneamente no Windows**, inicie primeiro o núcleo em uma janela de PowerShell independente dos aplicativos de IA, na pasta do projeto:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
.\.venv\Scripts\python.exe -m cyber_rag core --data-dir .\data --keep-alive --warmup
```

Espere a mensagem `[cyber-rag] Pronto`, mantenha essa janela aberta e depois conecte os clientes com os blocos gerados acima. `--warmup` carrega o modelo, abre o índice e executa uma consulta de preparação antes de disponibilizar o núcleo. Essa preparação pode demorar mais que o prazo de uma ferramenta MCP; acontece antes de aceitar consultas. `Ctrl+C` encerra o núcleo. `--keep-alive` desativa a saída por inatividade. Se outro núcleo já estiver ativo nessa base, o comando recusa iniciar uma segunda instância; encerre o núcleo manual na janela que o iniciou ou aguarde a saída por inatividade do núcleo automático.

`knowledge_status` descreve a base em disco; o perfil `semantic` não comprova que o modelo já está carregado na memória. No modo automático, a primeira busca ainda faz essa carga. Para validar a busca sem esperar pela carga dentro de uma chamada MCP, use o modo manual com `--warmup`.

Alguns clientes Windows colocam processos descendentes em um Job Object que encerra toda a árvore ao fechar o aplicativo. Por isso, a independência do núcleo iniciado automaticamente em relação ao cliente não está garantida nesta alfa. O núcleo manual fica fora dessa árvore. Se o núcleo reiniciar, cursores em memória expiram e a primeira consulta recarrega o modelo.

Guias oficiais: [Codex MCP](https://developers.openai.com/codex/mcp/), [Claude Desktop local MCP](https://modelcontextprotocol.io/docs/develop/connect-local-servers), [Claude Code MCP](https://code.claude.com/docs/en/mcp).

## Contrato das ferramentas

| Ferramenta | Uso |
|---|---|
| `knowledge_search` | Texto, filtros, limite, cursor e snapshot opcional; devolve passagens com fontes. |
| `knowledge_get_entity` | ID exato, como `attack:T1059.001` ou `cve:CVE-2021-44228`; mantém registros de cada fonte separados. |
| `knowledge_get_document` | ID retornado pela base; original ou seção, partes em base64 e hashes. |
| `knowledge_get_related` | Relações de um salto documentadas nas fontes, com evidência. |
| `knowledge_status` | Escopo, datas, perfil, contagens e última ingestão. |
| `knowledge_catalog` | Repositórios cadastrados, capacidades, caminhos OWASP conhecidos, estado do cache e contagens da memória. Sem consulta remota. |
| `knowledge_research` | Pesquisa conjunta por `query`, `source_ids`, `freshness`, `limit` de 1 a 3 por camada e `path` OWASP opcional. Pode coletar evidências e limpar notas expiradas. |
| `knowledge_get_cached_document` | Bytes de uma versão do cache, por ID, `revision` e `offset`; não consulta a rede. |
| `knowledge_remember` | Grava nota derivada de até 4.000 caracteres, com 1 a 8 referências verificáveis e validade de 1 a 90 dias, padrão 30. |
| `knowledge_forget` | Exclui uma nota pelo `memory_id`, preservando suas evidências de origem. |

As cinco primeiras ferramentas mantêm o contrato original somente leitura. Pesquisa e memória têm permissões próprias: `research` pode acessar origens externas aprovadas e escrever cache; `remember` escreve notas; `forget` exclui somente a nota indicada. Não trate as dez operações como globalmente somente leitura.

Use os campos `evidence_reference` retornados pela pesquisa para criar notas; não invente IDs, hashes ou URLs. A memória revalida as referências antes de responder, omite notas sem evidência atual e não conta como confirmação independente. Clientes que usam o mesmo diretório de dados compartilham a memória. Use somente notas reutilizáveis sem dados pessoais ou segredos.

Filtros: `source_ids`, `content_types`, `domains`, `platforms`, `product`, `entity_ids`, `lifecycle_status`, `published_from`, `published_to`, `kev_presence`, `cvss`. Datas exigem ISO 8601 com fuso; início inclusivo e final exclusivo. O CVSS exige versão, provedor, operador (`eq`, `gte`, `lte`, `gt`, `lt`) e valor. Campos diferentes combinam com AND; listas combinam com OR. `product` é correspondência nominal exata, não avaliação de versões afetadas.

IDs de fonte: `attack`, `owasp`, `sigma`, `cve`, `kev`, `nvd`. IDs de documento vêm das respostas. Reutilize `snapshot_id` ao abrir uma citação. Continue a paginação repetindo os mesmos argumentos e adicionando `cursor`; cursores expiram em quinze minutos ou ao reiniciar o núcleo.

O orçamento do contrato original de consultas ao snapshot é de 24.000 caracteres de conteúdo recuperado por resposta. Trechos de busca são explicitamente excertos. O original completo é recuperado por `knowledge_get_document`; junte as partes decodificadas e confira `original_hash`. Objetos extraídos de STIX/KEV também apontam para o documento do arquivo original, preservado integralmente. A pesquisa conjunta tem limites por camada e não oferece cursor; as versões do cache usam `knowledge_get_cached_document`, com `revision` fixa e `next_offset` até `last_part`.

A busca ignora trechos Markdown que contêm apenas títulos e aproveita até quatro trechos com conteúdo por documento, mantendo o teto de 3.600 caracteres por documento e de 1.800 por trecho. Quando o primeiro trecho e a seção seguinte cabem juntos em 1.800 caracteres, a seção seguinte acompanha o resultado como `adjacent_context`, com citação própria. Isso também funciona nos snapshots já existentes; o documento original e seus identificadores de seção continuam preservados.

`knowledge_get_document` também devolve `text`, uma visualização UTF-8 legível da parte quando possível, para a IA ler sem precisar decodificar base64. A representação exata continua em `content`; os limites incluem as duas representações. `complete` indica que aquela resposta contém o documento inteiro; `last_part` indica apenas o fim da paginação.

## Validar

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m cyber_rag import .\tests\fixtures\sources.json --data-dir .\data\smoke
.\.venv\Scripts\python.exe -m cyber_rag evaluate --data-dir .\data\smoke --benchmark .\tests\fixtures\smoke.json
```

Os dez checks sintéticos conferem contratos, relações e fidelidade dos bytes. As trinta perguntas em `evaluations/questions.json` definem o benchmark de respostas dos clientes. `evaluations/retrieval.json` acrescenta pré-requisitos de recuperação executáveis para 24 delas e registra seis pendências de cliente/ambiente isolado. Isso não representa trinta respostas aprovadas por GPT ou Claude. Veja [avaliação](docs/AVALIACAO.md) e [especificação](docs/ESPECIFICACAO_RAG_MCP.md).

`evaluations/pilot.json` contém onze verificações sobre as revisões reais registradas em [fontes e atribuição](docs/ORIGENS.md). O runner verifica as revisões antes de executar. Para essa base: `python -m cyber_rag evaluate --data-dir .\data --benchmark .\evaluations\pilot.json`. O comando compartilha o núcleo MCP; não abre uma segunda instância de Qdrant sobre o mesmo snapshot.

Para os pré-requisitos das 30 perguntas: `python -m cyber_rag evaluate --data-dir .\data --benchmark .\evaluations\retrieval.json`. Use `--split development` ou `--split acceptance` para avaliar cada conjunto. O relatório mantém respostas dos clientes como `not_evaluated` e distingue casos aprovados, falhos e pendentes.

## Limites desta versão

- O piloto é menor que a seleção final prevista. Não baixa todos os CVEs, todas as regras Sigma nem todo o ATT&CK para indexação.
- Não há interface gráfica, telemetria de máquinas, execução de ferramentas ofensivas ou diagnóstico de comprometimento.
- Não existe LLM dentro do servidor. O cliente pode enviar à OpenAI ou Anthropic os trechos recebidos; armazenamento local não torna a conversa inteiramente offline.
- O cliente controla suas políticas e permissões. Conteúdo recuperado não deve ser tratado como instrução; isso reduz o risco de prompt injection, sem garantir eliminá-lo.
- Qdrant local e inferência são serializados. Cancelar no cliente não interrompe à força uma inferência em andamento. O próximo pedido pode receber `BUSY`.
- A coleta remota usa trava própria e não ocupa a fila do snapshot enquanto espera a rede. Outra pesquisa ou operação de memória pode receber `BUSY`; a etapa local da pesquisa ainda compartilha o índice semântico.
- Apenas OWASP tem adaptador sob demanda. A descoberta por nomes pode não encontrar uma recomendação escondida no corpo de um arquivo ainda não coletado. O catálogo de caminhos não significa que todo o repositório foi indexado.
- O cache mantém até 1.000 versões e possui teto de 128 MiB; ao atingir o limite, recusa novas coletas e preserva o conteúdo anterior. Não há remoção automática de versões do cache nesta etapa.
- A memória tem até 1.000 notas e 8 MiB de texto, com expiração e exclusão. Referência válida comprova procedência, não que a conclusão escrita pela IA esteja correta.
- A busca retorna um conjunto limitado de candidatos, não uma exportação exaustiva do corpus. Dados antigos e conflitos permanecem identificados por fonte e data.
- Snapshots antigos são mantidos; ainda não há coleta automática de lixo. O disco cresce a cada atualização.
- Homologação nas interfaces reais de Codex/Claude e avaliação ampla de qualidade são etapas seguintes.

A extensão passou pela suíte geral de 216 testes, por verificações focadas posteriores e por uma consulta real via SDK MCP: dez ferramentas, coleta/reutilização do cache, integridade do original, memória offline e exclusão. Os 24 checks de recuperação anteriores continuam passando, com seis pendências. Isso não aprova as 30 respostas dos clientes; Claude permanece sem homologação. Veja [resultados e escopo](docs/IMPLEMENTACAO.md).

## Publicação e conteúdo de terceiros

O código é distribuído sob a [licença MIT](LICENSE), preservada do commit inicial do repositório. `data/`, `.local-data/`, `.venv/`, credenciais, pesos e as imagens de referência em `IMG/` ficam fora do Git. Os arquivos de conhecimento são baixados da origem por cada usuário. Licenças e avisos das fontes são preservados no manifesto e nos documentos originais; a licença do código não substitui as licenças do acervo.
