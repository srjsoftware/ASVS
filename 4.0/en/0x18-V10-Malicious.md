# V10: Malicious Code Verification Requirements

## Control Objective

Ensure that code satisfies the following high level requirements:

* Malicious activity is handled securely and properly  to not affect the rest of the application.
* Does not have time bombs or other time-based attacks.
* Does not "phone home" to malicious or unauthorized destinations.
* Does not have back doors, Easter eggs, salami attacks, rootkits, or unauthorized code that can be controlled by an attacker.

Finding malicious code is proof of the negative, which is impossible to completely validate. Best efforts should be undertaken to ensure that the code has no inherent malicious code or unwanted functionality.

## V10.1 Code Integrity Controls

The best defense against malicious code is "trust, but verify". Introducing unauthorized or malicious code into code is often a criminal offence in many jurisdictions. Policies and procedures should make sanctions regarding malicious code clear.

Lead developers should regularly review code check-ins, particularly those that might access time, I/O, or network functions.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **10.1.1** | Verify that a code analysis tool is in use that can detect potentially malicious code, such as time functions, unsafe file operations and network connections. | | | ✓ | 749 |

## V10.2 Malicious Code Search

Malicious code is extremely rare and is difficult to detect. Manual line by line code review can assist looking for logic bombs, but even the most experienced code reviewer will struggle to find malicious code even if they know it exists.

Complying with this section is not possible without complete access to source code, including third-party libraries.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **10.2.1** | Verify that the application source code and third party libraries do not contain unauthorized phone home or data collection capabilities. Where such functionality exists, obtain the user's permission for it to operate  before collecting any data. | | ✓ | ✓ | 359 |
| **10.2.2** | Verify that the application does not ask for unnecessary or excessive permissions to privacy related features or sensors, such as contacts, cameras, microphones, or location. | | ✓ | ✓ | 272 |
| **10.2.3** | Verify that the application source code and third party libraries do not contain back doors, such as hard-coded or additional undocumented accounts or keys, code obfuscation, undocumented binary blobs, rootkits, or anti-debugging, insecure debugging features, or otherwise out of date, insecure, or hidden functionality that could be used maliciously if discovered. | | | ✓ | 507 |
| **10.2.4** | Verify that the application source code and third party libraries do not contain time bombs by searching for date and time related functions. | | | ✓ | 511 |
| **10.2.5** | Verify that the application source code and third party libraries do not contain malicious code, such as salami attacks, logic bypasses, or logic bombs. | | | ✓ | 511 |
| **10.2.6** | Verify that the application source code and third party libraries do not contain Easter eggs or any other potentially unwanted functionality. | | | ✓ | 507 |

## V10.3 Deployed Application Integrity Controls

Once an application is deployed, malicious code can still be inserted. Applications need to protect themselves against common attacks, such as executing unsigned code from untrusted sources and subdomain takeovers.

Complying with this section is likely to be operational and continuous.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **10.3.1** | Verificar que se a aplicação possui uma funcionalidade de atualização automática de cliente ou servidor, atualizações devem ser obtidas sobre canais seguros e assinadas digitalmente. O código de atualização deve validar a assinatura digital da atualização antes de instalar ou executar a atualização. | ✓ | ✓ | ✓ | 16 |
| **10.3.2** | Verificar que a aplicação impõe proteções de integridade, tal como assinatura de código ou integridade de sub-recurso. A aplicação não deve carregar ou executar código de fontes não confiáveis, tal como carregar includes, módulos, plugins, código, ou bibliotecas de fontes não confiáveis ou da Internet. | ✓ | ✓ | ✓ | 353 |
| **10.3.3** | Verificar que a aplicação possui proteções contra a tomada de subdomínios se a aplicação depende de entradas de DNS e subdomínios de DNS, tal como nomes de domínio expirados, PTRs expirados ou CNAMEs, projetos expirados em repositórios públicos de código fonte, ou APIs em nuvem transiente, funções serverless, ou buckets de armazenamento (*autogen-bucket-id*.cloud.example.com) ou similar. Proteções podem incluir garantir que nomes de DNS utilizados pela aplicações são checados regularmente por expiração ou alteração. | ✓ | ✓ | ✓ | 350 |

## References

* [Hostile Subdomain Takeover, Detectify Labs](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)
* [Hijacking of abandoned subdomains part 2, Detectify Labs](https://labs.detectify.com/2014/12/08/hijacking-of-abandoned-subdomains-part-2/)
