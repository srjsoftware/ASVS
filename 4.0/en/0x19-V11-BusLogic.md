# V11: Business Logic Verification Requirements

## Control Objective

Ensure that a verified application satisfies the following high level requirements:

* The business logic flow is sequential, processed in order, and cannot be bypassed.
* Business logic includes limits to detect and prevent automated attacks, such as continuous small funds transfers, or adding a million friends one at a time, and so on.
* High value business logic flows have considered abuse cases and malicious actors, and have protections against spoofing, tampering, repudiation, information disclosure, and elevation of privilege attacks.

## V11.1 Business Logic Security Requirements

Business logic security is so individual to every application that no one checklist will ever apply. Business logic security must be designed in to protect against likely external threats - it cannot be added using web application firewalls or secure communications. We recommend the use of threat modeling during design sprints, for example using the OWASP Cornucopia or similar tools.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **11.1.1** | Verificar que a aplicação vai apenas processar fluxos de lógica de negócio para o mesmo usuário numa ordem de etapas sequencial e sem pular etapas. | ✓ | ✓ | ✓ | 841 |
| **11.1.2** | Verificar que a aplicação vai apenas processar fluxos de lógica de negócio em tempo realisticamente humano, i.e. transações não são submetidas muito rapidamente. | ✓ | ✓ | ✓ | 799 |
| **11.1.3** | Verificar que a aplicação possui limites apropriados para ações de negócio ou transações específicas que são corretamente aplicadas por usuário. | ✓ | ✓ | ✓ | 770 |
| **11.1.4** | Verificar que a aplicação possui controles anti-automação suficientes para detectar e proteger contra exfiltração de dados, requisições lógicas de negócio excessivas, envio de arquivos excessivo ou ataques de negação de serviço. | ✓ | ✓ | ✓ | 770 |
| **11.1.5** | Verificar que a aplicação possui limites de lógica de negócios ou validação para proteger contra riscos ou ameaças ao negócio mais prováveis, identificados utilizando modelagem de ameaças ou metodologias similares. | ✓ | ✓ | ✓ | 841 |
| **11.1.6** | Verify the application does not suffer from "Time Of Check to Time Of Use" (TOCTOU) issues or other race conditions for sensitive operations. | | ✓ | ✓ | 367 |
| **11.1.7** | Verify the application monitors for unusual events or activity from a business logic perspective. For example, attempts to perform actions out of order or actions which a normal user would never attempt. ([C9](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 754 |
| **11.1.8** | Verify the application has configurable alerting when automated attacks or unusual activity is detected. | | ✓ | ✓ | 390 |

## References

For more information, see also:

* [OWASP Web Security Testing Guide 4.1: Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README.html)
* Anti-automation can be achieved in many ways, including the use of [OWASP AppSensor](https://github.com/jtmelton/appsensor) and [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [OWASP AppSensor](https://github.com/jtmelton/appsensor) can also help with Attack Detection and Response.
* [OWASP Cornucopia](https://owasp.org/www-project-cornucopia/)
