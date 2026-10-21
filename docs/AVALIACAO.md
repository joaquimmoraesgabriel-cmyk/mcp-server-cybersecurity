# Avaliação da primeira implementação

A primeira alfa separa **testes determinísticos de recuperação** do **benchmark de respostas dos clientes**. Os testes automatizados usam documentos sintéticos isolados. As 30 perguntas da especificação continuam planejadas, sem gabaritos conferidos no corpus real e sem respostas de GPT ou Claude avaliadas.

Não há resultado medido de 95% de fidelidade, Recall@10, compatibilidade completa com clientes ou resistência a prompt injection. As metas da especificação são requisitos para a homologação futura.

## O que os testes verificam

`tests/fixtures/sources.json` descreve um corpus pequeno, criado para os testes:

| Fonte simulada | Conteúdo sintético |
| --- | --- |
| ATT&CK | Dois objetos com os IDs T1059 e T1059.001 e uma relação hierárquica explícita. |
| OWASP | Um Markdown sobre consultas parametrizadas, com bloco de código inerte e uma frase em português. |
| Sigma | Uma regra de teste para PowerShell com tag explícita `attack.t1059.001`. |
| CVE | CVE-2099-10001 publicada e CVE-2099-10002 rejeitada, ambas fictícias. |
| KEV | Uma entrada fictícia que referencia CVE-2099-10001. |

Os textos e URLs identificam o conteúdo como `SYNTHETIC TEST FIXTURE`. IDs de técnicas conhecidos testam o formato de consulta; seus textos não reproduzem ou substituem a documentação oficial. Os fixtures ficam fora do pacote Python e não são baixados ou importados automaticamente para a base do usuário.

`tests/fixtures/smoke.json` contém dez gabaritos determinísticos, conferidos diretamente nos arquivos de teste:

1. Recuperar a subtécnica pelo ID exato.
2. Recuperar a técnica pai sem substituí-la pela subtécnica.
3. Informar ausência de um ID desconhecido.
4. Conservar registros CVE e KEV separados para a mesma entidade.
5. Preservar o estado de uma CVE rejeitada na consulta exata.
6. Reconstruir os bytes originais da regra Sigma e verificar tamanho, limites e SHA-256.
7. Retornar a hierarquia ATT&CK com referência de evidência.
8. Retornar o mapeamento da tag Sigma com referência de evidência.
9. Recuperar passagens sobre PowerShell de ATT&CK e Sigma.
10. Buscar uma palavra em português que existe no Markdown sintético.

O décimo teste é lexical: ele não demonstra tradução, equivalência semântica multilíngue ou a qualidade do modelo de embeddings. A regra pequena também não substitui ensaios de paginação com originais grandes. Esses cenários exigem testes próprios.

Para executar os testes de avaliação, após instalar o projeto e suas dependências de desenvolvimento:

```powershell
python -m pytest tests/test_evaluation.py -q
```

O pytest cria um diretório temporário, importa apenas os fixtures e usa o perfil lexical. Não requer credenciais, download de modelos, rede, scanner ou API de GPT/Claude. Também verifica que um gabarito com hash incorreto falha, que um gabarito ligado a outro snapshot falha e que zero casos elegíveis nunca significa aprovação.

## Integração semântica opcional com pesos reais

`tests/test_semantic.py` usa o E5 e Qdrant reais quando o extra `semantic` e um modelo local já preparado estão disponíveis. Não substitui o encoder por vetores inventados. Sem esses requisitos, os testes aparecem como `skipped`, com o motivo; esse resultado não comprova funcionamento semântico.

Para executá-los, a variável `CYBER_RAG_TEST_MODEL_DIR` deve apontar para um diretório de dados preparado que contenha `model.json` e `models/<revisão SHA>`, ou diretamente para a pasta de pesos cujo nome seja essa revisão de 40 caracteres:

```powershell
$env:CYBER_RAG_TEST_MODEL_DIR = "D:\caminho\da\base-com-modelo"
python -m pytest tests/test_semantic.py -q -rs
```

Esses testes copiam ou criam hardlinks dos pesos imutáveis em uma base temporária. Ativam o modo offline das bibliotecas e bloqueiam operações reais de conexão via audit hook do Python durante a rodada. Não baixam modelos nem alteram a base indicada.

A rodada verifica dimensões e normalização dos vetores reais, limite de 512 tokens, recuperação vetorial para uma consulta sem correspondência lexical nos fixtures, reconstrução de índices em novos snapshots, consulta de uma geração anterior e preservação da geração válida após rejeitar um manifesto de modelo não suportado. Isso testa a integração e a separação de gerações. Não compara a qualidade de duas revisões reais de embeddings, não mede Recall@10 e não homologa o corpus público.

Na validação desta alfa, os **dois testes semânticos reais passaram**, sem skips, usando `intfloat/multilingual-e5-small` na revisão `614241f622f53c4eeff9890bdc4f31cfecc418b3`. O bloqueio de rede permaneceu ativo e nenhuma tentativa de conexão foi registrada. A rodada completa levou 105,85 segundos, incluindo importação das bibliotecas, preparação e vários carregamentos do modelo; esse tempo não representa a latência de uma consulta. Separadamente, os **nove testes do runner de avaliação passaram**, incluindo os dez smoke checks dos fixtures e a validação de revisões entre snapshots diferentes. Esses resultados não aprovam as 30 respostas de clientes planejadas.

## Runner de recuperação

A função `cyber_rag.evaluation.run_checks(data_dir, benchmark_path, use_core=True)` consulta um snapshot já preparado por meio das cinco ferramentas do núcleo compartilhado. Ela não cria ou atualiza a base, não executa conteúdo recuperado e não avalia a resposta final de um cliente. A CLI usa esse caminho para compartilhar o proprietário do Qdrant com os clientes MCP.

Na API Python, o padrão `use_core=False` abre o serviço no próprio processo e exige acesso exclusivo ao diretório de dados. Esse modo é usado pelos testes com bases temporárias isoladas; não deve disputar a mesma base vetorial com um núcleo já em execução. Encerrar a avaliação pelo núcleo compartilhado não encerra as conexões dos demais clientes.

Cada caso deve declarar `verification_status: "verified"` e um objeto `check` de tipo `entity`, `missing_entity`, `raw_document`, `relation` ou `search`. A avaliação fixa o snapshot durante a rodada. Quando o benchmark informa `source_revisions`, o runner compara todas as revisões com o estado publicado **antes** de executar a recuperação: uma fonte ausente ou divergente provoca falha. Gabaritos também podem informar um `snapshot_id` opcional para exigir uma geração local específica; um ID diferente provoca falha. Casos sem verificação são contabilizados como `skipped`.

O piloto real usa `source_revisions` e mantém `snapshot_id: null`. Assim, reindexar as mesmas fontes e a mesma seleção, inclusive em outra instalação ou perfil de busca, pode reutilizar os oráculos sem copiar um UUID de outra máquina. O relatório sempre registra o snapshot efetivamente consultado e a comparação das revisões. Revisões iguais não autorizam alterar silenciosamente a seleção: as evidências, hashes e limites de cobertura do gabarito continuam obrigatórios.

O resultado contém `status`, `snapshot_id`, `summary`, resultados por caso, contagens por conjunto e capacidades não avaliadas:

| Resultado | Significado |
| --- | --- |
| `passed` | Todos os casos elegíveis executados passaram, somente no escopo declarado pelo benchmark. |
| `failed` | Pelo menos um caso elegível falhou. |
| `not_evaluated` | Nenhum caso elegível foi executado. Não é aprovação. |

Sem um caminho de benchmark explícito, o runner retorna `not_evaluated`. Ele não presume que uma base de usuário contém dados sintéticos. Não há média de fidelidade nem pontuação de respostas de LLM neste relatório.

Somente uma base temporária importada de `tests/fixtures/sources.json` deve ser comparada a `tests/fixtures/smoke.json`. O benchmark sintético não serve para avaliar o corpus público real. Os arquivos de benchmark locais devem ser revisados antes de serem considerados gabaritos: marcar um caso como `verified` é uma declaração do autor do gabarito, não uma validação automática de fatos pelo programa.

## As 30 perguntas planejadas

`evaluations/questions.json` materializa Q01–Q30 da especificação. Cada pergunta contém conjunto, criticidade, evidência esperada, contexto, afirmações proibidas e estado do gabarito. Todas começam como `unverified`.

Os conjuntos mantêm a separação prevista:

- Desenvolvimento: Q01, Q03, Q05, Q07, Q09, Q10, Q12, Q13, Q14, Q15, Q16, Q17, Q18, Q19 e Q20.
- Aceitação: Q02, Q04, Q06, Q08, Q11, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29 e Q30.
- Críticos: Q06, Q08, Q11, Q21, Q22, Q23, Q26, Q28, Q29 e Q30.

O roteiro conserva duas variantes temporais para Q21, contexto fixo pendente para Q08/Q09 e a necessidade de ambientes isolados para Q27/Q29/Q30. Os fixtures de conflito CVE/NVD e de tentativa de prompt injection **ainda não foram criados ou avaliados**. Não estão incluídos nos dez smoke checks.

Executar esse JSON no runner atual produz 30 casos ignorados e `not_evaluated`. Promover casos requer conferir as evidências no snapshot real e acrescentar verificações executáveis adequadas. Questões que dependem de respostas dos clientes exigem outro roteiro de homologação; não devem ser convertidas em simples presença de palavras para alegar fidelidade.

## Corpus real e próximos critérios de homologação

O conector piloto busca uma seleção reduzida: T1059/T1059.001, cheat sheets selecionadas, uma regra Sigma, CVE-2021-44228 e o KEV do snapshot. Esse piloto permite testar os formatos. Ele ainda não representa a seleção de todas as CVEs do KEV mais 90 dias de publicações descrita como objetivo na especificação.

Para medir a qualidade real:

1. Congelar manifesto, revisões, modelo de embedding, perfil de busca e snapshot do corpus piloto.
2. Anotar gabaritos com documentos, passagens alternativas, entidades e relações sustentadas; confirmar as ausências no escopo.
3. Medir recuperação direta por conjunto, sem usar aceitação para ajustar pesos.
4. Homologar conexão e ferramentas em versões identificadas de Codex e Claude; registrar também sistema e modelo usados.
5. Conferir afirmações e citações das respostas, incluindo as três rodadas dos casos críticos.
6. Medir cobertura, consumo de recursos, latência, atualização, falhas e simultaneidade em corpus e hardware declarados.

Sucesso com fixtures demonstra comportamentos pontuais do software. A aprovação da release depende de evidências para as demais camadas previstas na especificação.
