# V8: Data Protection Verification Requirements

## Control Objective

There are three key elements to sound data protection: Confidentiality, Integrity and Availability (CIA). This standard assumes that data protection is enforced on a trusted system, such as a server, which has been hardened and has sufficient protections.

Applications have to assume that all user devices are compromised in some way. Where an application transmits or stores sensitive information on insecure devices, such as shared computers, phones and tablets, the application is responsible for ensuring data stored on these devices is encrypted and cannot be easily illicitly obtained, altered or disclosed.

Ensure that a verified application satisfies the following high level data protection requirements:

* Confidentiality: Data should be protected from unauthorized observation or disclosure both in transit and when stored.
* Integrity: Data should be protected from being maliciously created, altered or deleted by unauthorized attackers.
* Availability: Data should be available to authorized users as required.

## V8.1 General Data Protection

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **8.1.1** | Verify the application protects sensitive data from being cached in server components such as load balancers and application caches. | | ✓ | ✓ | 524 |
| **8.1.2** | Verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or purged/invalidated after the authorized user accesses the sensitive data. | | ✓ | ✓ | 524 |
| **8.1.3** | Verify the application minimizes the number of parameters in a request, such as hidden fields, Ajax variables, cookies and header values. | | ✓ | ✓ | 233 |
| **8.1.4** | Verify the application can detect and alert on abnormal numbers of requests, such as by IP, user, total per hour or day, or whatever makes sense for the application. | | ✓ | ✓ | 770 |
| **8.1.5** | Verify that regular backups of important data are performed and that test restoration of data is performed. | | | ✓ | 19 |
| **8.1.6** | Verify that backups are stored securely to prevent data from being stolen or corrupted. | | | ✓ | 19 |

## V8.2 Client-side Data Protection

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **8.2.1** | Verificar que a aplicação configura cabeçalhos anti-cache suficientes para que dados sensíveis não sejam armazenados na cache de navegadores modernos. | ✓ | ✓ | ✓ | 525 |
| **8.2.2** | Verificar que dados armazenados no armazenamento do navegador (como armazenamento local do HTML 5, armazenamento de sessão, IndexedDB ou cookies) não contenham dados sensíveis ou informações de identificação pessoal. | ✓ | ✓ | ✓ | 922 |
| **8.2.3** | Verificar que dados autenticados são limpos do armazenamento do client, como o DOM do navegador, após o cliente ou a sessão forem terminados. | ✓ | ✓ | ✓ | 922 |

## V8.3 Sensitive Private Data

This section helps protect sensitive data from being created, read, updated, or deleted without authorization, particularly in bulk quantities.

Compliance with this section implies compliance with V4 Access Control, and in particular V4.2. For example, to protect against unauthorized updates or disclosure of sensitive personal information requires adherence to V4.2.1. Please comply with this section and V4 for full coverage.

Note: Privacy regulations and laws, such as the Australian Privacy Principles APP-11 or GDPR, directly affect how applications must approach the implementation of storage, use, and transmission of sensitive personal information. This ranges from severe penalties to simple advice. Please consult your local laws and regulations, and consult a qualified privacy specialist or lawyer as required.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **8.3.1** | Verificar que dados sensíveis são enviados ao servidor no corpo da mensagem ou nos cabeçalhos HTTP, e que strings de parâmetros de requisições de qualquer verbo HTTP não contém dados sensíveis. | ✓ | ✓ | ✓ | 319 |
| **8.3.2** | Verificar que usuários possuem um método para remover ou exportar seus dados sob demanda. | ✓ | ✓ | ✓ | 212 |
| **8.3.3** | Verificar que é provido para o usuário linguagem clara a respeito da coleta e uso de informações pessoais fornecidas e que os usuários tenham provido consentimento para o uso dos dados antes que sejam usados de qualquer maneira. | ✓ | ✓ | ✓ | 285 |
| **8.3.4** | Verificar que todos os dados sensíveis criados ou processados pela aplicação tenham sido identificados, e garanta que uma política em como lidar com dados sensíveis está em vigor. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 200 |
| **8.3.5** | Verify accessing sensitive data is audited (without logging the sensitive data itself), if the data is collected under relevant data protection directives or where logging of access is required. | | ✓ | ✓ | 532 |
| **8.3.6** | Verify that sensitive information contained in memory is overwritten as soon as it is no longer required to mitigate memory dumping attacks, using zeroes or random data. | | ✓ | ✓ | 226 |
| **8.3.7** | Verify that sensitive or private information that is required to be encrypted, is encrypted using approved algorithms that provide both confidentiality and integrity. ([C8](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 327 |
| **8.3.8** | Verify that sensitive personal information is subject to data retention classification, such that old or out of date data is deleted automatically, on a schedule, or as the situation requires. | | ✓ | ✓ | 285 |

When considering data protection, a primary consideration should be around bulk extraction or modification or excessive usage. For example, many social media systems only allow users to add 100 new friends per day, but which system these requests came from is not important. A banking platform might wish to block more than 5 transactions per hour transferring more than 1000 euro of funds to external institutions. Each system's requirements are likely to be very different, so deciding on "abnormal" must consider the threat model and business risk. Important criteria are the ability to detect, deter, or preferably block such abnormal bulk actions.

## References

For more information, see also:

* [Consider using Security Headers website to check security and anti-caching headers](https://securityheaders.io)
* [OWASP Secure Headers project](https://owasp.org/www-project-secure-headers/)
* [OWASP Privacy Risks Project](https://owasp.org/www-project-top-10-privacy-risks/)
* [OWASP User Privacy Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [European Union General Data Protection Regulation (GDPR) overview](https://edps.europa.eu/data-protection_en)
* [European Union Data Protection Supervisor - Internet Privacy Engineering Network](https://edps.europa.eu/data-protection/ipen-internet-privacy-engineering-network_en)