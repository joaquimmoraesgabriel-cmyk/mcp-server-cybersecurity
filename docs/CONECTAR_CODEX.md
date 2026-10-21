# Conectar e validar no Codex

O servidor usa MCP por `stdio`: o Codex executa o adaptador local, que consulta o núcleo do RAG. Os passos abaixo usam a pasta `D:\mcp-server-cybersecurity` no Windows. Em outra instalação, ajuste a pasta e gere a configuração novamente. Um clone novo precisa primeiro seguir a instalação e a preparação da base no [README](../README.md).

A extensão sob demanda mantém as cinco consultas existentes e acrescenta catálogo, pesquisa conjunta, leitura do cache e gravação/exclusão de notas: são **dez ferramentas**. A configuração desta entrega reúne 38 fontes, incluindo as cinco do piloto. O [guia de fontes](FONTES.md) descreve escopos e restrições; o estado real é informado por `knowledge_catalog`. A [descrição do fluxo](PESQUISA_SOB_DEMANDA.md) explica quais operações acessam a rede ou alteram dados.

## Atualizar uma conexão existente

Após atualizar o código, encerre o núcleo na janela que o iniciou, usando `Ctrl+C`, e inicie-o novamente pelo comando abaixo. Se o núcleo foi iniciado automaticamente, use o mecanismo de encerramento do processo correspondente ou aguarde sua saída por inatividade; não remova arquivos de trava para forçar uma segunda instância. Depois recarregue o servidor MCP no cliente, ou feche e abra o aplicativo, para renovar a lista de ferramentas.

O núcleo novo anuncia internamente `tool_contract: 3`. Se um adaptador novo encontrar um núcleo antigo, as novas ferramentas retornam `CORE_UPGRADE_REQUIRED`, pedindo reinício. As configurações `stdio`, o diretório `data/`, o snapshot e o modelo preparado continuam os mesmos. **Não execute outra importação apenas para habilitar essas ferramentas ou fontes remotas.**

Atualize também as dependências com `uv sync --locked --no-install-project`, acrescentando `--extra semantic` se usa esse perfil, antes de reiniciar. A extração de PDF usa `pypdf` 6.21.2. Uma mudança na configuração de fonte pode deixar seu cache `unknown` até nova coleta/verificação; não apague o banco. O recarregamento compatível preserva os bytes originais e atualiza a representação pesquisável. Uma observação antiga no cache não invalida um snapshot verificado mais recentemente apenas por apresentar revisão diferente.

## 1. Iniciar o núcleo

Na máquina de desenvolvimento original, o ambiente e a base semântica já estão preparados. Abra uma janela de PowerShell independente do Codex e execute:

```powershell
Set-Location 'D:\mcp-server-cybersecurity'
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
.\.venv\Scripts\python.exe -m cyber_rag core --data-dir .\data --keep-alive --warmup
```

Espere a mensagem `[cyber-rag] Pronto` e deixe essa janela aberta. `--warmup` carrega o modelo, abre o índice e exercita a busca antes de aceitar consultas MCP. Uma falha de preparação encerra o comando sem anunciar que o núcleo está pronto. `Ctrl+C` encerra o núcleo. Se aparecer que outro núcleo já possui a base, ele já está em execução: encerre o núcleo manual na janela que o iniciou ou aguarde a saída por inatividade do núcleo automático antes de iniciar este comando. Não é necessário iniciar outra instância para cada cliente.

O modo manual mantém o núcleo disponível quando um cliente Windows fecha sua árvore de processos. A preparação pode demorar mais que os 120 segundos do prazo interno de uma consulta, dependendo da máquina; espere a confirmação de prontidão antes de validar no Codex. Depois, o núcleo reutiliza o modelo. O perfil `semantic` de `knowledge_status` descreve o índice em disco e não indica, sozinho, que o modelo já está carregado.

## 2. Adicionar a configuração do Codex

A configuração global padrão do Codex fica em `%USERPROFILE%\.codex\config.toml`. Se você usa um `CODEX_HOME` personalizado, edite o `config.toml` desse diretório. O mesmo arquivo é usado pelos clientes locais do mesmo host. Este procedimento segue a [documentação oficial de MCP](https://developers.openai.com/codex/mcp/).

Em uma segunda janela de PowerShell, gere o bloco para esta máquina:

```powershell
Set-Location 'D:\mcp-server-cybersecurity'
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
.\.venv\Scripts\python.exe -m cyber_rag config --client codex --data-dir .\data
```

Na máquina de desenvolvimento, o mesmo bloco já está salvo em `data/client-config/codex.toml`. Abra a configuração do Codex:

```powershell
notepad "$env:USERPROFILE\.codex\config.toml"
```

Acrescente o bloco gerado, mantendo as demais configurações. Se já existir uma entrada `cyber-rag`, atualize essa entrada para evitar tabelas duplicadas. O bloco desta máquina é:

```toml
[mcp_servers.cyber-rag]
command = 'D:\mcp-server-cybersecurity\.venv\Scripts\python.exe'
args = ['-m', 'cyber_rag', 'serve', '--data-dir', 'D:\mcp-server-cybersecurity\data']
tool_timeout_sec = 150

[mcp_servers.cyber-rag.env]
PYTHONPATH = 'D:\mcp-server-cybersecurity\src'
```

Aspas simples em TOML mantêm as barras dos caminhos Windows literais. O arquivo gerado pelo comando usa aspas duplas e barras escapadas; as duas formas são válidas. O prazo de 150 segundos dá margem à primeira carga do modelo.

Salve, feche e abra novamente o Codex para carregar a configuração. Abra uma conversa local no projeto. Se sua versão apresentar a opção de reiniciar servidores MCP, ela também pode recarregar o servidor.

Com a CLI instalada, `codex mcp get cyber-rag` confere a configuração e `codex mcp list` mostra o cadastro. Esses comandos não comprovam uma consulta à base: a validação funcional é o próximo passo.

## 3. Validar dentro do Codex

Envie as mensagens abaixo, uma por vez. Peça o uso explícito das ferramentas para distinguir uma resposta do RAG de uma resposta produzida sem consulta.

**Conexão e cobertura:**

> Use a ferramenta knowledge_status do servidor cyber-rag. Informe o snapshot ativo, o perfil de recuperação, o número de documentos e as fontes disponíveis. Não use shell nem pesquisa na web.

Na base inicial desta máquina, o snapshot contém cinco fontes (`attack`, `owasp`, `sigma`, `cve`, `kev`), perfil semântico e 1.774 documentos. A expansão por URLs não altera essa contagem: as fontes remotas e seus caches aparecem separadamente. Uma nova importação pode mudar a geração; confira os valores efetivamente retornados.

**Consulta exata:**

> Use knowledge_get_entity do cyber-rag para consultar cve:CVE-2021-44228. Explique o que as fontes locais registram e cite suas URLs e o snapshot. Preserve a distinção entre as fontes.

**Busca em português:**

> Use knowledge_search do cyber-rag para buscar recomendações sobre armazenamento seguro de senhas. Resuma a orientação encontrada, cite a fonte e informe se a evidência cobre a pergunta.

**Ausência explícita:**

> Use knowledge_get_entity do cyber-rag para buscar attack:T9999.999. Se não houver resultado, explique a ausência apenas no snapshot local, sem concluir que o identificador nunca existiu.

Verifique se o Codex realmente chamou as ferramentas `knowledge_*`, se o resultado não contém erro e se a resposta cita evidências retornadas. Cadastrar o servidor ou obter uma resposta bem escrita, por si só, não confirma o funcionamento do RAG.

## 4. Validar pesquisa sob demanda e memória

Primeiro inspecione a extensão:

> Use knowledge_catalog do cyber-rag. Liste as fontes disponíveis com seus IDs, exigências de consulta e política de validade. Informe os caminhos conhecidos e versões no cache por fonte. Não confunda fontes cadastradas, caminhos catalogados, arquivos coletados e documentos do snapshot.

Depois teste a coleta explícita:

> Use knowledge_research com query="armazenamento de senhas", source_ids=["owasp"], freshness="refresh" e limit=1. Separe o snapshot, o cache de fontes e a memória. Informe os estados por fonte em layers.source_cache.sources, revisão, checked_at e freshness; não diga que a verificação deu certo se houver falha ou cooldown.

Repita com `freshness="offline"`. A ferramenta deve reutilizar o conteúdo local disponível sem acessar a rede. Abra o resultado com `knowledge_get_cached_document`, preservando o `document_id` e a `revision` retornados; siga `next_offset` se for preciso ler todas as partes. O cache não é consultado por `knowledge_get_document`, que continua operando sobre snapshots.

Valide em seguida uma fonte por chamada, usando o mesmo procedimento de coleta, leitura e repetição offline:

| Fonte | `query` de exemplo | O que conferir |
| --- | --- | --- |
| `attack` | `T1059.001` | Bundle de ATT&CK Enterprise, revisão e evidência da técnica. |
| `sigma` | `powershell` | Regra textual do repositório, caminho e revisão. Nenhuma regra é executada. |
| `cve` | `CVE-2021-44228` | Registro CVE recuperado por ID exato. |
| `kev` | `CVE-2021-44228` | Entrada no catálogo KEV preservado, com revisão e data. |
| `nvd` | `CVE-2021-44228` | Registro da NVD, separado da fonte CVE e do KEV. |
| `cwe` | `CWE-79` | Registro da fraqueza, com revisão e data individuais. |

Para as outras fontes, copie `example_query` e leia `query_requirement` e `access_note` no catálogo. Depois faça uma consulta conjunta:

> Use knowledge_research com query="CVE-2021-44228", source_ids=["cve","kev","nvd"], freshness="auto" e limit=3. Informe o resultado e o estado de cada fonte. Preserve divergências e datas. Repita em offline e compare as revisões retornadas, sem afirmar que offline verificou a origem.

Há limite de três fontes por chamada online, até 64 filtros offline, orçamento compartilhado de 90 segundos e 24.000 caracteres de evidências. Falha ou limite em uma origem deve aparecer identificado e preservar os resultados disponíveis das demais. O estado agregado `federated` não atesta sucesso de todas as fontes. Ao atingir prazo ou limite, uma consulta específica pode ser necessária; não repita automaticamente se houver `retry_at`.

Para conferir PDF, use um caminho conhecido da fonte `vx-papers`:

> Use knowledge_research com query="enumerate processes", source_ids=["vx-papers"], path="An Alternative Method To Enumerate Processes.pdf", freshness="auto" e limit=1. Informe a revisão, o hash do original e os metadados de extração. Distinga o texto derivado do PDF original, diga se há páginas sem texto e não afirme que foi feito OCR. Depois repita em offline e compare a referência retornada.

Essa fonte permite somente 15 artigos selecionados, sendo 14 PDFs e um TXT; não é todo o VX-Underground. O parser tem limites de 16 MiB, 100 páginas, 2 MiB de texto, 512 MiB de memória e até dez segundos. Não executa JavaScript, anexos ou código e não abre links. Os controles limitam recursos do processo; não constituem uma sandbox de segurança. A extração pode perder layout e conteúdo de imagens. Leia as partes do original com `knowledge_get_cached_document` somente quando necessário e confira seu hash após reconstrução; `partial` na paginação não significa cobertura visual completa. Os 31 testes específicos do parser foram executados no Windows; o caminho POSIX ainda não foi exercitado nessa rodada.

Ao conferir cobertura, `unprotect` corresponde às descrições principais do repositório de contribuições — 376 caminhos na descoberta de 21/10/2026 — e `capa` apresentou 1.055 regras, incluindo experimentais em `nursery/`. Esses números não são documentos já baixados. `malapi` teve falha de DNS nessa verificação, com zero evidências; deve informar a indisponibilidade, sem atribuir conteúdo de outra origem ao MalAPI. O catálogo em execução é a referência para o estado atual.

Valide as fontes de governança também uma por chamada:

| Fonte | `query` de exemplo | O que conferir |
| --- | --- | --- |
| `nist-csf` | `GV.OC` | Edição CSF 2.0, versão do catálogo OSCAL e commit, preservando a distinção entre esses campos. |
| `nist-800-53` | `Account Management` | Rev. 5, versão do catálogo e controles/procedimentos efetivamente retornados. |
| `cis-controls` | `Control 1 inventory` | Página CAS do controle escolhido, revisão individual e termos CC BY-NC-ND 4.0. |
| `lgpd` | `LGPD princípios dados pessoais` | Origem Câmara dos Deputados, hash e data; não atribuir a resposta ao endpoint Planalto. |
| `gdpr` | `Article 5 personal data` | Use separadamente `path="gdpr-original-en.html"` e `path="gdpr-consolidated-en.html"`; informe a publicação e o corrigendum identificado, sem presumir alterações posteriores. |
| `iso27001` | `ISO 27001` | Somente metadados abertos de edições e suplementos; não atribuir requisitos ou Annex A à evidência. O CSV original tem aproximadamente 60 MB, com até 90 segundos por operação dentro do prazo restante compartilhado; esse teto não é tempo esperado. Sua paginação não é necessária para a consulta comum. |

Repita em `offline` e confira se ID, revisão e hash permanecem verificáveis. Revalidar um recurso jurídico fixo não comprova que ele contém a legislação mais recente. Consultar fontes de controles ou normas também não comprova a conformidade de uma organização. Veja as [URLs e condições de cada fonte](FONTES.md#fontes-de-governança-normas-e-legislação).

Para testar memória, use uma nota curta e não sensível, apoiada em uma evidência atual da pesquisa:

> Grave explicitamente com knowledge_remember uma nota sobre a evidência que acabamos de recuperar, copiando o evidence_reference da ferramenta e usando ttl_days=1. Informe o memory_id e confirme que trust continua derived_unverified. Não salve a conversa inteira nem dados pessoais.

Pesquise termos presentes na nota com `knowledge_research` em modo `offline` e confira `layers.memory`. A busca das notas é lexical. Por fim, peça `knowledge_forget` com o ID exato dessa nota de teste e repita a busca. A nota deve desaparecer, enquanto o documento de origem continua disponível. `EVIDENCE_NOT_CURRENT` na gravação exige revalidar a fonte; não invente uma referência para contornar o erro.

Esse roteiro observa chamadas reais no cliente. Não substitui o benchmark de 30 respostas nem homologa automaticamente o Claude. Os ensaios anteriores pelo SDK oficial via `stdio` e núcleo autenticado estão em [Implementação](IMPLEMENTACAO.md), com seu escopo histórico. Confira o contrato do processo em execução após cada atualização; ter o código novo em disco não atualiza um núcleo já aberto.

## Se houver erro

| Sintoma | Verificação |
|---|---|
| `cyber-rag` não aparece | Confira o `config.toml` do host local, reinicie o Codex e abra uma conversa local. |
| `No module named cyber_rag` | Confira `PYTHONPATH`, a pasta `src` e o executável da `.venv`. |
| Erro ao ler TOML | Confira barras e aspas; evite duplicar `[mcp_servers.cyber-rag]`. |
| `INDEX_UNAVAILABLE` | Confira os caminhos da base e execute `doctor`; em um clone novo, prepare o corpus antes de consultar. |
| `TIMEOUT` na primeira busca | A chamada expirou, mas a carga pode continuar no núcleo; uma tentativa imediata pode receber `BUSY`. Nas próximas inicializações, use `--warmup` e espere `Pronto` antes de consultar. Mantenha `tool_timeout_sec = 150`. |
| `BUSY` | Aguarde a operação atual e repita; inferência e índice vetorial são serializados nesta alfa. |
| `CORE_UPGRADE_REQUIRED` | Reinicie o núcleo com o código novo e recarregue a conexão MCP para descobrir as dez ferramentas. |
| Fonte com `remote_status=failed`, `cooldown` ou `budget_exhausted` | Leia o estado daquela fonte, os avisos e `retry_at` em `knowledge_catalog`; versões locais disponíveis podem continuar consultáveis, mas não foram revalidadas. Não repita em loop. |
| `EVIDENCE_NOT_CURRENT` | Confira os IDs, hashes e revisões retornados, além do estado de verificação; a memória exige evidências atuais e verificáveis. |
| Caminho ou identificador não encontrado | Confira `query_requirement`, `example_query` e caminhos no catálogo. `path` exige uma fonte explícita; a ferramenta não aceita URLs ou arquivos arbitrários. |
| Mais fontes no catálogo que no snapshot | É esperado: `knowledge_search` consulta só o snapshot; `knowledge_research` também consulta os caches. Cadastro não significa conteúdo já coletado. |
| `freshness=current` em uma resposta offline | A cópia ainda está dentro da política de validade da última verificação; isso não indica uma nova consulta remota nem validação factual. |
| `source_configuration_changed` ou cache `unknown` após atualização | Consulte a fonte com a configuração nova e respeite `retry_at`. A representação será revalidada; os bytes antigos permanecem preservados. Não apague o banco nem trate esse estado como evidência removida. |
| MalAPI configurado, mas sem evidências | A origem oficial apresentou falha de DNS em 21/10/2026. Confira o estado atual e o intervalo de nova tentativa; cadastro não comprova disponibilidade. |
| `pdf_dependency_unavailable`, `pdf_timeout`, `pdf_*_limit` ou `pdf_no_text` | Confira as dependências e o erro específico. PDFs podem exceder os limites ou conter apenas imagens; não há OCR nem retorno silencioso de texto após uma falha de extração. `pdf_resource_limit_unavailable` indica que o processo não conseguiu aplicar o limite do sistema operacional. |

Para conferir ambiente e executar o piloto fora da interface do Codex, use o segundo PowerShell com `PYTHONPATH` configurado:

```powershell
.\.venv\Scripts\python.exe -m cyber_rag doctor --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag evaluate --data-dir .\data --benchmark .\evaluations\pilot.json
```

O piloto tem onze verificações. A homologação das respostas no Codex continua dependendo das chamadas e evidências observadas na interface.
