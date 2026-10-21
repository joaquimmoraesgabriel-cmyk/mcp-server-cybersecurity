# Dados sintéticos para testes

Todos os arquivos desta pasta foram escritos para o teste do software. Não são cópias das publicações ATT&CK, OWASP, Sigma, CVE ou CISA e não devem orientar decisões de segurança. Os IDs ATT&CK servem para testar formatos; textos, autores, URLs e CVEs são fixtures sintéticos.

O manifesto `sources.json` importa apenas os cinco subdiretórios de fontes. O arquivo `smoke.json` contém verificações com gabaritos conferidos exclusivamente nestes fixtures. O manifesto não aponta para arquivos pessoais, não baixa dados e não executa comandos ou regras. Os exemplos em Markdown e YAML devem permanecer dados inertes.

Use um diretório temporário isolado para importar este manifesto. Não misture estes documentos com a base de uso. O benchmark de 30 perguntas reais em `evaluations/questions.json` é um roteiro separado, ainda sem gabaritos verificados por snapshot.
