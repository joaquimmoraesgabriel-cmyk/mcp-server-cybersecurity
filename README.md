# Cyber RAG MCP — evidências locais e pesquisa sob demanda

Servidor MCP local para consultar evidências de cibersegurança. A IA recebe trechos e fontes verificáveis; o aplicativo cliente produz a resposta. Versão **0.1.0a1**, em desenvolvimento.

O servidor combina o snapshot local já preparado, caches de fontes obtidas por URLs cadastradas e uma memória separada de notas derivadas. A configuração desta entrega reúne 38 fontes, descritas no [catálogo de cobertura e restrições](docs/FONTES.md); cadastro não comprova disponibilidade ou coleta completa. `knowledge_search` consulta somente o snapshot; use `knowledge_research` para pesquisar nas três camadas. Veja o [fluxo, as garantias e os limites](docs/PESQUISA_SOB_DEMANDA.md).

O ambiente, o piloto e o modelo são preparados localmente com os comandos abaixo. Veja a [entrega e os resultados](docs/IMPLEMENTACAO.md) e o [guia para conectar e validar no Codex](docs/CONECTAR_CODEX.md). Na máquina de desenvolvimento original, `.venv/`, `data/` e os blocos em `data/client-config/` já estão preparados; essas pastas não acompanham o clone do repositório.

Validação desta expansão: **681 testes passaram** e **37 fontes retornaram evidências pelo MCP**. O MalAPI está cadastrado, mas seu endereço oficial ficou indisponível. Os testes exercitam amostras, consultas conjuntas e memória; não afirmam ingestão completa nem homologação das respostas dos clientes. Consulte o [relatório com limites e resultados](evaluations/results/2026-10-21-multisource-summary.json).

O projeto roda no computador de quem instala. A compatibilidade pretendida nesta etapa é **Codex, para modelos GPT, e Claude Desktop/Claude Code**, por MCP `stdio`. Não há autenticação da marca do modelo: qualquer cliente que execute o programa com acesso local pode falar MCP. O ChatGPT na web não acessa diretamente este processo `stdio`.

## O que já existe

- Dez ferramentas MCP: cinco consultas ao snapshot, catálogo de fontes, pesquisa conjunta, leitura do cache e gravação/exclusão explícitas de notas.
- Importação de ATT&CK STIX 2.1, OWASP Markdown, Sigma YAML, CVE JSON 5 e KEV. NVD 2.0 pode ser importado de arquivos locais.
- Piloto oficial com commits fixados: duas técnicas ATT&CK, cinco cheat sheets, uma regra Sigma, CVE-2021-44228 e catálogo KEV completo no commit selecionado. É uma seleção inicial, não a cobertura completa planejada.
- SQLite com busca exata e BM25. Perfil semântico opcional: E5 multilingual local e Qdrant local, fusão RRF. Sem reranker nesta versão.
- Snapshots imutáveis, troca atômica do índice ativo, citações e originais com SHA-256. Arquivos grandes são paginados em base64 sem alterar BOM ou finais de linha.
- Um núcleo local compartilhado entre clientes, com comunicação autenticada em loopback. A pesquisa consulta fontes públicas cadastradas e persiste evidências; o MCP não expõe shell, scanner nem administração dos snapshots.
- Catálogo de fontes com assuntos, URLs, formatos, exemplos e política de validade. A descoberta usa caminhos de repositórios, arquivos agregados ou identificadores exatos de APIs, conforme a fonte. O cache incremental preserva bytes e SHA-256 e usa busca lexical; o snapshot semântico existente permanece separado.
- Memória local com referências obrigatórias, prazo de validade e invalidação quando a evidência muda. Notas são sempre `derived_unverified`; não treinam o modelo nem capturam automaticamente a conversa.
- Extração de texto de PDFs selecionados com `pypdf` 6.21.2 em processo separado com limites de recursos. Não faz OCR nem executa conteúdo ativo; preserva o PDF original e identifica o texto como representação derivada.

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

`sync-pilot` acessa a rede para baixar a seleção do piloto. O manifesto registra hashes, commits, licenças e o escopo. Erros de parsing ou quarentena impedem publicar a nova geração. As cinco consultas ao snapshot funcionam sem rede. Executar novamente o comando cria outra geração; não há agendamento automático. Esse comando não importa automaticamente todas as fontes do catálogo remoto. `knowledge_research` pode coletar evidências em caches separados, sem reconstruir essa geração.

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
.\.venv\Scripts\python.exe -m cyber_rag research 'T1059.001' --source attack --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'powershell' --source sigma --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'CVE-2021-44228' --source cve --source kev --source nvd --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'CWE-79' --source cwe --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'Control 1 inventory' --source cis-controls --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'ISO 27001' --source iso27001 --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'password storage' --source owasp --freshness offline --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag research 'powershell' --freshness offline --data-dir .\data
```

`auto` respeita a validade de cada fonte: atualmente uma hora para CVE/NVD/KEV e 24 horas para a maioria das demais; confira `freshness_seconds` no catálogo. `refresh` solicita nova verificação e respeita bloqueios temporários após falhas; `offline` não faz requisições externas. Sem filtro, o modo offline consulta os caches existentes. A pesquisa mantém `layers.snapshot`, `layers.source_cache` e `layers.memory` separados, com datas e falhas próprias. Estado `current` não comprova correção factual nem acesso à origem nesta chamada.

Use `catalog` ou `knowledge_catalog` para obter os IDs disponíveis, exemplos e restrições de cada fonte. A descoberta por nomes não lê antecipadamente todos os documentos. GitHub/GitLab usam revisões fixadas; fontes HTTP preservam uma versão local por hash, embora a URL de origem possa mudar. CVE/NVD, CWE e eventos Windows exigem os identificadores indicados no catálogo. A pergunta completa não é enviada como busca aos repositórios; requisições por identificador revelam à API o ID consultado. `--path` exige uma única fonte explícita e um caminho permitido, como `--source owasp --path cheatsheets/Password_Storage_Cheat_Sheet.md`. Não são aceitas URLs livres.

Cada chamada online aceita até três fontes; chamadas offline aceitam até 64 filtros de fontes. Há orçamento compartilhado de 90 segundos e de 24.000 caracteres de evidências. Para investigar muitas fontes, faça chamadas menores e confira os estados de cada uma em `layers.source_cache.sources`.

Alguns escopos exigem atenção: `vx-papers` permite somente 15 artigos selecionados, sendo 14 PDFs e um TXT; não consulta todo o corpus VX-Underground. Na descoberta verificada em 21/10/2026, `unprotect` apresentou 376 descrições do repositório oficial de contribuições e `capa`, 1.055 regras, incluindo as experimentais em `nursery/`. Esses números são caminhos catalogados, não documentos já coletados. O conector `malapi` está configurado, mas a origem apresentou falha de DNS nessa verificação e retornou zero evidências; não houve substituição silenciosa por outra fonte. Consulte o [escopo e as restrições](docs/PESQUISA_SOB_DEMANDA.md#catálogo-e-descoberta).

Em governança, o catálogo inclui NIST CSF 2.0 e SP 800-53 Rev. 5 em OSCAL, páginas da especificação de avaliação CIS Controls v8, LGPD atualizada na Câmara e duas publicações oficiais do GDPR no Cellar. A fonte `iso27001` oferece **somente metadados abertos de edições e suplementos**, sem texto normativo. As publicações GDPR são fixas, de 2016 e com corrigendum de 2018; reverificar seus bytes não descobre alterações legais posteriores. Edições, termos e URLs estão em [Fontes](docs/FONTES.md#fontes-de-governança-normas-e-legislação).

Para atualizar uma instalação existente, reinicie o núcleo e recarregue a conexão MCP no cliente para descobrir as dez ferramentas. Não é necessário reimportar o piloto nem baixar novamente o modelo. Um núcleo antigo retorna `CORE_UPGRADE_REQUIRED` nas novas operações; siga o [guia de atualização e validação](docs/CONECTAR_CODEX.md).

Se a configuração de um adaptador mudar, evidências antigas podem ficar `unknown` até nova coleta/verificação. O recarregamento da mesma revisão preserva os bytes originais e atualiza a representação pesquisável; não apague o cache para resolver esse estado. Uma observação antiga do cache não invalida um snapshot verificado mais recentemente apenas por ter outra revisão.

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
| `knowledge_search` | Busca somente no snapshot: texto, filtros, limite, cursor e snapshot opcional; devolve passagens com fontes. |
| `knowledge_get_entity` | ID exato, como `attack:T1059.001` ou `cve:CVE-2021-44228`; mantém registros de cada fonte separados. |
| `knowledge_get_document` | ID retornado pela base; original ou seção, partes em base64 e hashes. |
| `knowledge_get_related` | Relações de um salto documentadas nas fontes, com evidência. |
| `knowledge_status` | Escopo, datas, perfil, contagens e última ingestão do snapshot; capacidades remotas são informadas separadamente. |
| `knowledge_catalog` | Fontes cadastradas, capacidades, caminhos conhecidos, estado de cada cache e contagens da memória. Sem consulta remota. |
| `knowledge_research` | Pesquisa conjunta por `query`, `source_ids`, `freshness`, `limit` de 1 a 3 por camada e `path` opcional para uma fonte explícita. Pode coletar evidências e limpar notas expiradas. |
| `knowledge_get_cached_document` | Bytes de uma versão do cache, por ID, `revision` e `offset`; não consulta a rede. |
| `knowledge_remember` | Grava nota derivada de até 4.000 caracteres, com 1 a 8 referências verificáveis e validade de 1 a 90 dias, padrão 30. |
| `knowledge_forget` | Exclui uma nota pelo `memory_id`, preservando suas evidências de origem. |

As cinco primeiras ferramentas mantêm o contrato original somente leitura. Pesquisa e memória têm permissões próprias: `research` pode acessar origens externas aprovadas e escrever cache; `remember` escreve notas; `forget` exclui somente a nota indicada. Não trate as dez operações como globalmente somente leitura.

Use os campos `evidence_reference` retornados pela pesquisa para criar notas; não invente IDs, hashes ou URLs. A memória revalida as referências antes de responder, omite notas sem evidência atual e não conta como confirmação independente. Clientes que usam o mesmo diretório de dados compartilham a memória. Use somente notas reutilizáveis sem dados pessoais ou segredos.

Filtros da busca no snapshot: `source_ids`, `content_types`, `domains`, `platforms`, `product`, `entity_ids`, `lifecycle_status`, `published_from`, `published_to`, `kev_presence`, `cvss`. Datas exigem ISO 8601 com fuso; início inclusivo e final exclusivo. O CVSS exige versão, provedor, operador (`eq`, `gte`, `lte`, `gt`, `lt`) e valor. Campos diferentes combinam com AND; listas combinam com OR. `product` é correspondência nominal exata, não avaliação de versões afetadas. Esses filtros não são todos parâmetros de `knowledge_research`.

Os IDs das fontes disponíveis vêm de `knowledge_catalog`; exemplos são `attack`, `owasp`, `sigma`, `cve`, `kev`, `nvd` e `cwe`. Uma fonte cadastrada pode ainda não ter documentos no cache nem no snapshot. IDs de documento vêm das respostas. Reutilize `snapshot_id` ao abrir uma citação do snapshot. Continue a paginação dessas consultas repetindo os mesmos argumentos e adicionando `cursor`; cursores expiram em quinze minutos ou ao reiniciar o núcleo.

O orçamento do contrato original de consultas ao snapshot é de 24.000 caracteres de conteúdo recuperado por resposta. Trechos de busca são explicitamente excertos. O original completo é recuperado por `knowledge_get_document`; junte as partes decodificadas e confira `original_hash`. Objetos extraídos de STIX/KEV também apontam para o documento do arquivo original, preservado integralmente. A pesquisa conjunta compartilha seu próprio teto de 24.000 caracteres entre as três camadas e não oferece cursor; as versões do cache usam `knowledge_get_cached_document`, com `revision` fixa e `next_offset` até `last_part`.

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
- A descoberta por nomes pode não encontrar uma recomendação escondida no corpo de um arquivo ainda não coletado. O catálogo de caminhos não significa que todo o repositório foi indexado; APIs por ID não oferecem busca geral do acervo.
- PDFs têm limite de 16 MiB, 100 páginas e 2 MiB de texto derivado. A extração pode perder ordem de leitura, tabelas e conteúdo de imagens; não faz OCR. O processo tem teto de 512 MiB e até dez segundos, mas não oferece sandbox de segurança nem isolamento do sistema de arquivos. Veja os [controles do parser](docs/PESQUISA_SOB_DEMANDA.md#extração-de-texto-de-pdf).
- Cada novo cache limita versões, bytes originais e tamanho físico do SQLite. O teto global de 4 GiB é conferido antes de cada fonte: uma operação pode ultrapassá-lo antes de as seguintes passarem ao modo local. Não há remoção automática de versões do cache; veja os [limites por armazenamento](docs/PESQUISA_SOB_DEMANDA.md#recursos-e-segurança).
- A memória tem até 1.000 notas e 8 MiB de texto, com expiração e exclusão. Referência válida comprova procedência, não que a conclusão escrita pela IA esteja correta.
- A busca retorna um conjunto limitado de candidatos, não uma exportação exaustiva do corpus. Dados antigos e conflitos permanecem identificados por fonte e data.
- Snapshots antigos são mantidos; ainda não há coleta automática de lixo. O disco cresce a cada atualização.
- Homologação nas interfaces reais de Codex/Claude e avaliação ampla de qualidade são etapas seguintes.

O histórico da primeira extensão OWASP registra uma suíte de 216 testes, verificações focadas e consulta real via SDK MCP, além de 24 pré-requisitos de recuperação aprovados e seis pendências. Esses números não são a contagem de testes da expansão multifontes nem aprovam as 30 respostas dos clientes. Veja [resultados e escopo](docs/IMPLEMENTACAO.md).

## Publicação e conteúdo de terceiros

O código é distribuído sob a [licença MIT](LICENSE), preservada do commit inicial do repositório. `data/`, `.local-data/`, `.venv/`, credenciais, pesos e as imagens de referência em `IMG/` ficam fora do Git. Os arquivos de conhecimento são baixados da origem por cada usuário. Licenças e avisos das fontes são preservados no manifesto e nos documentos originais; a licença do código não substitui as licenças do acervo.
