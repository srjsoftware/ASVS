# V14: Configuration Verification Requirements

## Control Objective

Ensure that a verified application has:

* A secure, repeatable, automatable build environment.
* Hardened third party library, dependency and configuration management such that out of date or insecure components are not included by the application.
* A secure-by-default configuration, such that administrators and users have to weaken the default security posture.

Configuration of the application out of the box should be safe to be on the Internet, which means a safe out of the box configuration.

## V14.1 Build

Build pipelines are the basis for repeatable security - every time something insecure is discovered, it can be resolved in the source code, build or deployment scripts, and tested automatically. We are strongly encouraging the use of build pipelines with automatic security and dependency checks that warn or break the build to prevent known security issues being deployed into production. Manual steps performed irregularly directly leads to avoidable security mistakes.

As the industry moves to a DevSecOps model, it is important to ensure the continued availability and integrity of deployment and configuration to achieve a "known good" state. In the past, if a system was hacked, it would take days to months to prove that no further intrusions had taken place. Today, with the advent of software defined infrastructure, rapid A/B deployments with zero downtime, and automated containerized builds, it is possible to automatically and continuously build, harden, and deploy a "known good" replacement for any compromised system.

If traditional models are still in place, then manual steps must be taken to harden and back up that configuration to allow the compromised systems to be quickly replaced with high integrity, uncompromised systems in a timely fashion.

Compliance with this section requires an automated build system, and access to build and deployment scripts.

| # | Description | L1 | L2 | L3 | CWE |
| --- | --- | --- | --- | -- | -- |
| **14.1.1** | Verificar que os processos de construição e implantação da aplicação são realizados de maneira segura e repetível, tal como automação CI / CD, gerenciamento de configurações automático, e scripts de implantação automáticos. | | ✓ | ✓ | |
| **14.1.2** | Verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to break the build if an unsafe pointer, memory, format string, integer, or string operations are found. |  | ✓ | ✓ | 120 |
| **14.1.3** | Verify that server configuration is hardened as per the recommendations of the application server and frameworks in use. | | ✓ | ✓ | 16 |
| **14.1.4** | Verify that the application, configuration, and all dependencies can be re-deployed using automated deployment scripts, built from a documented and tested runbook in a reasonable time, or restored from backups in a timely fashion. | | ✓ | ✓ | |
| **14.1.5** | Verify that authorized administrators can verify the integrity of all security-relevant configurations to detect tampering. | | | ✓ | |

## V14.2 Dependency

Dependency management is critical to the safe operation of any application of any type. Failure to keep up to date with outdated or insecure dependencies is the root cause of the largest and most expensive attacks to date.

Note: At Level 1, 14.2.1 compliance relates to observations or detections of client-side and other libraries and components, rather than the more accurate build-time static code analysis or dependency analysis. These more accurate techniques could be discoverable by interview as required.

| # | Description | L1 | L2 | L3 | CWE |
| --- | --- | --- | --- | -- | -- |
| **14.2.1** | Verificar que todos os componentes estão atualizados, preferencialmente utilizando checagem de dependência durante a construção ou compilação. ([C2](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 1026 |
| **14.2.2** | Verificar que toda funcionalidade, documentação, exemplos e configuração desnecessárias são removidas, tal como aplicações de exemplo, documentações de plataforma, e usuários padrão ou de exemplo. | ✓ | ✓ | ✓ | 1002 |
| **14.2.3** | Verificar que se recursos de aplicação, como bibliotecas JavaScript, CSS ou fontes web, são armazenados externamente ou em uma Rede de Fornecimento de Conteúdo (CDN) ou provedor externo, Integridade de Sub-recurso (SRI) é usada para validar a integridade do recurso. | ✓ | ✓ | ✓ | 829 |
| **14.2.4** | Verify that third party components come from pre-defined, trusted and continually maintained repositories. ([C2](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 829 |
| **14.2.5** | Verify that an inventory catalog is maintained of all third party libraries in use. ([C2](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | |
| **14.2.6** | Verify that the attack surface is reduced by sandboxing or encapsulating third party libraries to expose only the required behaviour into the application. ([C2](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 265 |

## V14.3 Unintended Security Disclosure Requirements

Configurations for production should be hardened to protect against common attacks, such as debug consoles, raise the bar for Cross-site Scripting (XSS) and Remote File Inclusion (RFI) attacks, and to eliminate trivial information discovery "vulnerabilities" that are the unwelcome hallmark of many penetration testing reports. Many of these issues are rarely rated as a significant risk, but they are chained together with other vulnerabilities. If these issues are not present by default, it raises the bar before most attacks can succeed.

| # | Description | L1 | L2 | L3 | CWE |
| --- | --- | --- | --- | -- | -- |
| **14.3.1** | Verificar que as mensagens de erro do servidor web ou de aplicação e do framework são configurados para transmitir respostas customizadas acionáveis pelo usuário para eliminar qualquer revelação de segurança não intencional. | ✓ | ✓ | ✓ | 209 |
| **14.3.2** | Verificar que os modos de depuração do servidor web ou de aplicação e do framework da aplicação estão desabilitados em produção para eliminar funcionalidades de depuração, consoles de desenvolvedor e revelações de segurança não intencionais. | ✓ | ✓ | ✓ | 497 |
| **14.3.3** | Verificar que os cabeçalhos HTTP ou qualquer parte da resposta HTTP não exponha informações de versões de componentes de sistema detalhada. | ✓ | ✓ | ✓ | 200 |

## V14.4 HTTP Security Headers Requirements

| # | Description | L1 | L2 | L3 | CWE |
| --- | --- | --- | --- | -- | -- |
| **14.4.1** | Verificar que toda reposta HTTP contém um cabeçalho Content-Type. Tipos de conteúdo text/*, */*+xml e application/xml devem também especificar um conjunto de caracteres seguros (e.g., UTF-8, ISO-8859-1). | ✓ | ✓ | ✓ | 173 |
| **14.4.2** | Verificar que toda resposta de API contém um cabeçalho Content-Disposition: attachment; filename="api.json" (ou outro nome de arquivo apropriado parar o tipo do conteúdo). | ✓ | ✓ | ✓ | 116 |
| **14.4.3** | Verificar que um cabeçalho de Política de Segurança de Conteúdo (CSP) está configurado de forma que ajude a mitigar o impacto de ataques XSS como vulnerabilidades de injeção de HTML, DOM, JSON e JavaScript. | ✓ | ✓ | ✓ | 1021 |
| **14.4.4** | Verificar que todas as respostas contém um cabeçalho X-Content-Type-Options: nosniff. | ✓ | ✓ | ✓ | 116 |
| **14.4.5** | Verificar que um cabeçalho de Strict-Transport-Security  é incluído em todas as respostas de todos os subdomínios, tal como Strict-Transport-Security: max-age=15724800; includeSubdomains. | ✓ | ✓ | ✓ | 523 |
| **14.4.6** | Verificar que um cabeçalho "Referrer-Policy" adequado está incluído, tal como "no-referrer" ou "same-origin". | ✓ | ✓ | ✓ | 116 |
| **14.4.7** | Verificar que o conteúdo de uma aplicação web não pode ser embutido em um site de terceiros por padrão e que o embutimento do recurso específico é permitido apenas onde necessário ao se usar os cabeçalhos Content-Security-Policy: frame-ancestors e X-Frame-Options adequados. | ✓ | ✓ | ✓ | 346 |

## V14.5 Validate HTTP Request Header Requirements

| # | Description | L1 | L2 | L3 | CWE |
| --- | --- | --- | --- | -- | -- |
| **14.5.1** | Verificar que o servidor de aplicação aceita apenas os métodos HTTP utilizados pela aplicação/API, incluindo o uso prévio de OPTIONS, e loga/alerta qualquer requisição que não é válida para o contexto da aplicação. | ✓ | ✓ | ✓ | 749 |
| **14.5.2** | Verificar que o cabeçalho Origin fornecido não é utilizado para autenticação ou qualquer decisão de controle de acesso, visto que o cabeçalho Origin pode ser facilmente alterado pelo atacante. | ✓ | ✓ | ✓ | 346 |
| **14.5.3** | Verificar que o cabeçalho de compartilhamento de recursos com origens diferentes Access-Control-Allow-Origin usa uma lista de permissões de domínios e subdomínios confiáveis restrita para checagem e não suporta a origem "null". | ✓ | ✓ | ✓ | 346 |
| **14.5.4** | Verify that HTTP headers added by a trusted proxy or SSO devices, such as a bearer token, are authenticated by the application. | | ✓ | ✓ | 306 |

## References

For more information, see also:

* [OWASP Web Security Testing Guide 4.1: Testing for HTTP Verb Tampering]( https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering.html)
* Adding Content-Disposition to API responses helps prevent many attacks based on misunderstanding on the MIME type between client and server, and the "filename" option specifically helps prevent [Reflected File Download attacks.](https://www.blackhat.com/docs/eu-14/materials/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf)
* [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [Exploiting CORS misconfiguration for BitCoins and Bounties](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OWASP Web Security Testing Guide 4.1: Configuration and Deployment Management Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README.html)
* [Sandboxing third party components](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html#sandboxing-content)
