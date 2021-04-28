# V5: Validation, Sanitization and Encoding Verification Requirements

## Control Objective

The most common web application security weakness is the failure to properly validate input coming from the client or the environment before directly using it without any output encoding. This weakness leads to almost all of the significant vulnerabilities in web applications, such as Cross-Site Scripting (XSS), SQL injection, interpreter injection, locale/Unicode attacks, file system attacks, and buffer overflows.

Ensure that a verified application satisfies the following high-level requirements:

* Input validation and output encoding architecture have an agreed pipeline to prevent injection attacks.
* Input data is strongly typed, validated, range or length checked, or at worst, sanitized or filtered.
* Output data is encoded or escaped as per the context of the data as close to the interpreter as possible.

With modern web application architecture, output encoding is more important than ever. It is difficult to provide robust input validation in certain scenarios, so the use of safer API such as parameterized queries, auto-escaping templating frameworks, or carefully chosen output encoding is critical to the security of the application.

## V5.1 Input Validation Requirements

Properly implemented input validation controls, using positive allow lists and strong data typing, can eliminate more than 90% of all injection attacks. Length and range checks can reduce this further. Building in secure input validation is required during application architecture, design sprints, coding, and unit and integration testing. Although many of these items cannot be found in penetration tests, the results of not implementing them are usually found in V5.3 - Output encoding and Injection Prevention Requirements. Developers and secure code reviewers are recommended to treat this section as if L1 is required for all items to prevent injections.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **5.1.1** | Verificar que a aplicação possui defesas contra ataques de poluição de parâmetros  HTTP, principalmente se o framework da aplicação não faz distinção sobre a fonte de parâmetros da requisição (GET, POST, cookies, cabeçalhos ou variáveis de ambiente). | ✓ | ✓ | ✓ | 235 |
| **5.1.2** | Verificar que os frameworks protegem contra ataques de atribuição de parâmetros em massa ou se a aplicação possui medidas defensivas para proteger contra a atribuição de parâmetros insegura, como marcar campos como privados ou algo similar. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 915 |
| **5.1.3** | Verificar que todas as entradas (campos de formulário HTML, requisições REST, parâmetros de URL, cabeçalhos HTTP, cookies, arquivos em lote, feeds RSS etc.) são validadas usando validação positiva (lista de permissão). ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 20 |
| **5.1.4** | Verificar que os dados estruturados são fortemente tipados e validados em relação a um esquema definido incluindo caracteres, comprimento e padrão permitidos (por exemplo, números de cartão de crédito ou telefone, ou validação da relação entre dois campos, como verificar se cidade e CEP/código postal correspondem). ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 20 |
| **5.1.5** | Verificar se redirecionamento e encaminhamento de URLs permitem apenas destinos autorizados na lista de permissões ou mostram um aviso ao redirecionar para conteúdo potencialmente não confiável. | ✓ | ✓ | ✓ | 601 |

## V5.2 Sanitization and Sandboxing Requirements

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **5.2.1** | Verificar que todas as entradas HTML não confiáveis de editores WYSIWYG ou similares são devidamente sanitizadas com uma biblioteca de sanitização HTML ou recurso do framework. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 116 |
| **5.2.2** | Verificar que os dados não estruturados são sanitizados para impor medidas de segurança como caracteres e comprimento permitidos. | ✓ | ✓ | ✓ | 138 |
| **5.2.3** | Verificar que a aplicação sanitiza a entrada de dados do usuário antes de passar para os sistemas de e-mail para se proteger contra a injeção de SMTP ou IMAP. | ✓ | ✓ | ✓ | 147 |
| **5.2.4** | Verificar que a aplicação evita o uso de eval () ou outros recursos de execução dinâmica de código. Onde não há alternativa, qualquer entrada do usuário sendo incluída deve ser sanitizada ou colocada em sandbox antes de ser executada. | ✓ | ✓ | ✓ | 95 |
| **5.2.5** | Verificar que a aplicação protege contra ataques de injeção de template, garantindo que qualquer entrada do usuário incluída seja sanitizada ou colocada em sandbox. | ✓ | ✓ | ✓ | 94 |
| **5.2.6** | Verificar que a aplicação protege contra ataques SSRF, validando ou sanitizando dados não confiáveis ou metadados de arquivos HTTP, como nomes de arquivos e campos de entrada de URL, usando uma lista de protocolos, domínios, caminhos e portas permitidos. | ✓ | ✓ | ✓ | 918 |
| **5.2.7** | Verificar que a aplicação sanitiza, desativa ou executa em sandbox o conteúdo de script em Scalable Vector Graphics (SVG) fornecido pelo usuário, especialmente por estarem relacionados a XSS resultante de scripts inline e ForeignObjects. | ✓ | ✓ | ✓ | 159 |
| **5.2.8** | Verificar que a aplicação sanitiza, desativa ou executa em sandbox o conteúdo de expressões de linguagem de templates ou de script fornecidos pelo usuário, como Markdown, folhas de estilo CSS ou XSL, BBCode ou similar. | ✓ | ✓ | ✓ | 94 |

## V5.3 Output Encoding and Injection Prevention Requirements

Output encoding close or adjacent to the interpreter in use is critical to the security of any application. Typically, output encoding is not persisted, but used to render the output safe in the appropriate output context for immediate use. Failing to output encode will result in an insecure, injectable, and unsafe application.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **5.3.1** | Verificar que a codificação de saída é relevante para o intérprete e o contexto necessários. Por exemplo, use codificadores especificamente para valores HTML, atributos HTML, JavaScript, parâmetros de URL, cabeçalhos HTTP, SMTP e outros conforme o contexto exigir, especialmente de entradas não confiáveis (por exemplo, nomes com Unicode ou apóstrofes, como ね こ ou O'Hara). ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 116 |
| **5.3.2** | Verificar que a codificação de saída preserva o conjunto de caracteres e a localidade escolhidos pelo usuário, de forma que qualquer ponto de caractere Unicode é válido e tratado com segurança. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 176 |
| **5.3.3** | Verificar que o escape de saída sensível ao contexto, de preferência automatizado - ou, na pior das hipóteses, manual - protege contra XSS refletido, armazenado e baseado em DOM. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 79 |
| **5.3.4** | Verificar que a seleção de dados ou as consultas ao banco de dados (por exemplo, SQL, HQL, ORM, NoSQL) usam consultas parametrizadas, ORMs, entidades de frameworks ou estão, de outra forma, protegidas contra ataques de injeção de banco de dados. ([C3](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 89 |
| **5.3.5** | Verificar que onde os mecanismos parametrizados ou mais seguros não estão presentes, a codificação de saída específica do contexto é usada para proteger contra ataques de injeção, como o uso de escape de SQL para proteger contra injeção de SQL. ([C3, C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 89 |
| **5.3.6** | Verificar que a aplicação protege contra ataques de injeção de JavaScript ou JSON, incluindo para ataques de eval(), includes remotos de JavaScript, burlar a Política de Segurança de Conteúdo (CSP), DOM XSS e avaliação da expressão JavaScript. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 830 |
| **5.3.7** | Verificar que a aplicação protege contra vulnerabilidades de injeção de LDAP ou se controles de segurança específicos para impedir a injeção LDAP foram implementados. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 90 |
| **5.3.8** | Verificar que a aplicação protege contra injeção de comandos de SO e que as chamadas ao sistema operacional usam requisições parametrizadas ou usam codificação de linha de comando contextual. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 78 |
| **5.3.9** | Verificar que a aplicação protege contra ataques de inclusão de arquivo local (LFI) ou inclusão de arquivo remoto (RFI). | ✓ | ✓ | ✓ | 829 |
| **5.3.10** | Verificar que a aplicação protege contra ataques de injeção de XPath ou de injeção de XML. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 643 |

Note: Using parameterized queries or escaping SQL is not always sufficient; table and column names, ORDER BY and so on, cannot be escaped. The inclusion of escaped user-supplied data in these fields results in failed queries or SQL injection.

Note: The SVG format explicitly allows ECMA script in almost all contexts, so it may not be possible to block all SVG XSS vectors completely. If SVG upload is required, we strongly recommend either serving these uploaded files as text/plain or using a separate user supplied content domain to prevent successful XSS from taking over the application.

## V5.4 Memory, String, and Unmanaged Code Requirements

The following requirements will only apply when the application uses a systems language or unmanaged code.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **5.4.1** | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. |  | ✓ | ✓ | 120 |
| **5.4.2** | Verify that format strings do not take potentially hostile input, and are constant. |  | ✓ | ✓ | 134 |
| **5.4.3** | Verify that sign, range, and input validation techniques are used to prevent integer overflows. |  | ✓ | ✓ | 190 |

## V5.5 Deserialization Prevention Requirements

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **5.5.1** | [DELETED] | | | | |
| **5.5.2** | Verificar que a aplicação restringe corretamente os analisadores XML para usar apenas a configuração mais restritiva possível e para garantir que recursos não seguros, como a resolução de entidades externas, estejam desabilitados para impedir ataques de XML External Entities (XXE).  | ✓ | ✓ | ✓ | 611 |
| **5.5.3** | [MODIFIED] Verificar que a desserialização de dados não confiáveis é evitada ou protegida ao filtrar os dados de desserialização que chegam. | ✓ | ✓ | ✓ | 502 |
| **5.5.4** | Verificar que ao analisar JSON em navegadores ou backends baseados em JavaScript, JSON.parse é usado para analisar o documento JSON. Não use eval () para analisar JSON. | ✓ | ✓ | ✓ | 95 |

## References

For more information, see also:

* [OWASP Testing Guide 4.0: Input Validation Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README.html)
* [OWASP Cheat Sheet: Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
* [OWASP Testing Guide 4.0: Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.html)
* [OWASP LDAP Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Testing Guide 4.0: Client Side Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/)
* [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP DOM Based Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
* [OWASP Java Encoding Project](https://owasp.org/owasp-java-encoder/)
* [OWASP Mass Assignment Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
* [DOMPurify - Client-side HTML Sanitization Library](https://github.com/cure53/DOMPurify)
* [XML External Entity (XXE) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

For more information on auto-escaping, please see:

* [Reducing XSS by way of Automatic Context-Aware Escaping in Template Systems](https://googleonlinesecurity.blogspot.com/2009/03/reducing-xss-by-way-of-automatic.html)
* [AngularJS Strict Contextual Escaping](https://docs.angularjs.org/api/ng/service/$sce)
* [AngularJS ngBind](https://docs.angularjs.org/api/ng/directive/ngBind)
* [Angular Sanitization](https://angular.io/guide/security#sanitization-and-security-contexts)
* [Angular Security](https://angular.io/guide/security)
* [ReactJS Escaping](https://reactjs.org/docs/introducing-jsx.html#jsx-prevents-injection-attacks)
* [Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

For more information on deserialization, please see:

* [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [OWASP Deserialization of Untrusted Data Guide](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
