# Conectar e validar no Codex

O servidor usa MCP por `stdio`: o Codex executa o adaptador local, que consulta o núcleo do RAG. Os passos abaixo usam a pasta `D:\mcp-server-cybersecurity` no Windows. Em outra instalação, ajuste a pasta e gere a configuração novamente. Um clone novo precisa primeiro seguir a instalação e a preparação da base no [README](../README.md).

A extensão sob demanda mantém as cinco consultas existentes e acrescenta catálogo, pesquisa conjunta, leitura do cache e gravação/exclusão de notas: são **dez ferramentas**. Somente OWASP tem coleta sob demanda nesta etapa. A [descrição do fluxo](PESQUISA_SOB_DEMANDA.md) explica quais operações acessam a rede ou alteram dados.

## Atualizar uma conexão existente

Após atualizar o código, encerre o núcleo na janela que o iniciou, usando `Ctrl+C`, e inicie-o novamente pelo comando abaixo. Se o núcleo foi iniciado automaticamente, use o mecanismo de encerramento do processo correspondente ou aguarde sua saída por inatividade; não remova arquivos de trava para forçar uma segunda instância. Depois recarregue o servidor MCP no cliente, ou feche e abra o aplicativo, para renovar a lista de ferramentas.

O núcleo novo anuncia internamente `tool_contract: 2`. Se um adaptador novo encontrar um núcleo antigo, as novas ferramentas retornam `CORE_UPGRADE_REQUIRED`, pedindo reinício. As configurações `stdio`, o diretório `data/`, o snapshot e o modelo preparado continuam os mesmos. **Não execute outra importação apenas para habilitar essas ferramentas.**

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

Na base inicial desta máquina, espere cinco fontes (`attack`, `owasp`, `sigma`, `cve`, `kev`), perfil semântico e 1.774 documentos. Uma atualização pode mudar as contagens e o snapshot; confira os valores efetivamente retornados.

**Consulta exata:**

> Use knowledge_get_entity do cyber-rag para consultar cve:CVE-2021-44228. Explique o que as fontes locais registram e cite suas URLs e o snapshot. Preserve a distinção entre as fontes.

**Busca em português:**

> Use knowledge_search do cyber-rag para buscar recomendações sobre armazenamento seguro de senhas. Resuma a orientação encontrada, cite a fonte e informe se a evidência cobre a pergunta.

**Ausência explícita:**

> Use knowledge_get_entity do cyber-rag para buscar attack:T9999.999. Se não houver resultado, explique a ausência apenas no snapshot local, sem concluir que o identificador nunca existiu.

Verifique se o Codex realmente chamou as ferramentas `knowledge_*`, se o resultado não contém erro e se a resposta cita evidências retornadas. Cadastrar o servidor ou obter uma resposta bem escrita, por si só, não confirma o funcionamento do RAG.

## 4. Validar pesquisa sob demanda e memória

Primeiro inspecione a extensão:

> Use knowledge_catalog do cyber-rag. Informe quais fontes suportam consulta sob demanda, quantos caminhos OWASP são conhecidos e quantas versões estão no cache. Não confunda caminhos catalogados com documentos coletados.

Depois teste a coleta explícita:

> Use knowledge_research com query="armazenamento de senhas", source_ids=["owasp"], freshness="refresh" e limit=1. Separe o snapshot, o cache de fontes e a memória. Informe remote_status, revisão, checked_at e freshness; não diga que a verificação deu certo se houver falha ou cooldown.

Repita com `freshness="offline"`. A ferramenta deve reutilizar o conteúdo local disponível sem acessar a rede. Abra o resultado com `knowledge_get_cached_document`, preservando o `document_id` e a `revision` retornados; siga `next_offset` se for preciso ler todas as partes. O cache não é consultado por `knowledge_get_document`, que continua operando sobre snapshots.

Para testar memória, use uma nota curta e não sensível, apoiada em uma evidência atual da pesquisa:

> Grave explicitamente com knowledge_remember uma nota sobre a evidência que acabamos de recuperar, copiando o evidence_reference da ferramenta e usando ttl_days=1. Informe o memory_id e confirme que trust continua derived_unverified. Não salve a conversa inteira nem dados pessoais.

Pesquise termos presentes na nota com `knowledge_research` em modo `offline` e confira `layers.memory`. A busca das notas é lexical. Por fim, peça `knowledge_forget` com o ID exato dessa nota de teste e repita a busca. A nota deve desaparecer, enquanto o documento de origem continua disponível. `EVIDENCE_NOT_CURRENT` na gravação exige revalidar a fonte; não invente uma referência para contornar o erro.

Esse roteiro observa chamadas reais no cliente. Não substitui o benchmark de 30 respostas nem homologa automaticamente o Claude. A extensão foi validada pelo SDK oficial via `stdio` e núcleo autenticado, incluindo cache, memória e exclusão; os resultados estão em [Implementação](IMPLEMENTACAO.md). No ambiente original, o núcleo já foi atualizado e preparado. Recarregue a conexão no Codex para redescobrir as dez ferramentas.

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
| Pesquisa com `remote_status=failed` ou `cooldown` | Leia os avisos e `retry_at` em `knowledge_catalog`; versões locais continuam disponíveis, mas não foram revalidadas. Não repita em loop. |
| `EVIDENCE_NOT_CURRENT` | Confira os IDs, hashes e revisões retornados, além do estado de verificação; a memória exige evidências atuais e verificáveis. |
| Caminho OWASP não encontrado | Consulte `knowledge_catalog` e use um caminho existente; a ferramenta não aceita URLs ou arquivos arbitrários. |

Para conferir ambiente e executar o piloto fora da interface do Codex, use o segundo PowerShell com `PYTHONPATH` configurado:

```powershell
.\.venv\Scripts\python.exe -m cyber_rag doctor --data-dir .\data
.\.venv\Scripts\python.exe -m cyber_rag evaluate --data-dir .\data --benchmark .\evaluations\pilot.json
```

O piloto tem onze verificações. A homologação das respostas no Codex continua dependendo das chamadas e evidências observadas na interface.
