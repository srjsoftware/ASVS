# V4: Access Control Verification Requirements

## Control Objective

Authorization is the concept of allowing access to resources only to those permitted to use them. Ensure that a verified application satisfies the following high level requirements:

* Persons accessing resources hold valid credentials to do so.
* Users are associated with a well-defined set of roles and privileges.
* Role and permission metadata is protected from replay or tampering.

## Security Verification Requirements

## V4.1 General Access Control Design

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **4.1.1** | Verificar que a aplicação impões regras de controle de acesso em uma camada de serviço confiável, especialmente se controle de acesso do lado do cliente está presente e pode ser burlado. | ✓ | ✓ | ✓ | 602 |
| **4.1.2** | Verificar que todos os atributos de usuário e de dados, e informações de políticas usados pelo controle de acesso não podem ser manipulados pelos usuários finais, a não ser que for especificamente autorizado. | ✓ | ✓ | ✓ | 639 |
| **4.1.3** | Verificar que o princípio do menor privilégio existe - usuários devem ser capazes apenas de acessar funções, dados de arquivo, URLs, controladores, serviços e outros recursos  para os quais eles possuem autorização específica. Isto implica proteções contra spoofing e elevação de privilégio. ([C7](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ |  285 |
| **4.1.4** | Verificar que o princípio de negar por padrão existe através do qual novos usuários/papéis iniciam com permissões mínimas ou sem permissões; e usuários/papéis não recebem acesso a novas funcionalidades até que o acesso seja explicitamente atribuído. ([C7](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ |  276 |
| **4.1.5** | Verificar que os controles de acesso falham de maneira segura, incluindo quando uma exceção ocorre. ([C10](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ |  285 |

## V4.2 Operation Level Access Control

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **4.2.1** | Verificar que dados sensíveis de APIs estão protegidos contra ataques de Referências Diretas a Ojbetos Inseguras (IDOR) alvejando criação, leitura, atualização ou deleção de registros, como criar ou atualizar os registros de outra pessoal, visualizar os registros de todo mundo ou apagar todos os registros. | ✓ | ✓ | ✓ | 639 |
| **4.2.2** | Verificar se a aplicação ou framework impõe mecanismos anti-CSRF fortes para proteger funcionalidades autenticadas e anti-automação ou anti-CSRF protegem efetivamente funcionalidades autenticadas. | ✓ | ✓ | ✓ | 352 |

## V4.3 Other Access Control Considerations

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **4.3.1** | Verificar que interfaces administrativas utilizam autenticação multi-fator apropriavada para proteger contra uso não autorizado. | ✓ | ✓ | ✓ | 419 |
| **4.3.2** | Verificar que navegação por diretório está desabilitada a não ser que seja deliberadamente desejada. Adicionalmente, aplicações não deveriam permitir o descobrimento ou a revelação de metadados de arquivos ou diretórios, como Thumbs.db, .DS_store e pastas .git ou .svn. | ✓ | ✓ | ✓ | 548 |
| **4.3.3** | Verify the application has additional authorization (such as step up or adaptive authentication) for lower value systems, and / or segregation of duties for high value applications to enforce anti-fraud controls as per the risk of application and past fraud. |  | ✓ | ✓ |  732 |

## References

For more information, see also:

* [OWASP Testing Guide 4.0: Authorization](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/05-Authorization_Testing/README.html)
* [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
* [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [OWASP REST Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
