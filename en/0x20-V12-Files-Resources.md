# V12: File and Resources Verification Requirements

## Control Objective

Ensure that a verified application satisfies the following high level requirements:

* Untrusted file data should be handled accordingly and in a secure manner.
* Untrusted file data obtained from untrusted sources are stored outside the web root and with limited permissions.

## V12.1 File Upload Requirements

Although zip bombs are eminently testable using penetration testing techniques, they are considered L2 and above to encourage design and development consideration with careful manual testing, and to avoid automated or unskilled manual penetration testing of a denial of service condition.

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.1.1** | Verificar que a aplicação não irá aceitar arquivos grandes que poderiam encher o armazenamento ou causar negação de serviço. | ✓ | ✓ | ✓ | 400 |
| **12.1.2** | Verificar que arquivos compactados são checados por "bombas zip" - pequenos arquivos enviados que descompactados se tornam arquivos imensos, deste modo, exaurindo os limites de armazenamento de arquivos. | | ✓ | ✓ | 409 |
| **12.1.3** | Verificar que uma quota de tamanho de arquivo e número máximo de arquivos por usuários é imposta para garantir que um único usuário não pode encher o armazenamento com varios arquivos, ou arquivos excessivamente grandes. | | ✓ | ✓ | 770 |

## V12.2 File Integrity Requirements

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.2.1** | Verify that files obtained from untrusted sources are validated to be of expected type based on the file's content. | | ✓ | ✓ | 434 |

## V12.3 File Execution Requirements

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.3.1** | Verificar que metadados de nome de arquivo submetidos pelo usuário não são utilizados diretamente pelo sistema ou sistema de arquivos do framework e que uma API de URL é utilizada para proteger contra path traversal. | ✓ | ✓ | ✓ | 22 |
| **12.3.2** | Verificar que metadados de nome de arquivo submetidos pelo usuário são validados ou ignorados para prevenir a revelação, criação, atualização ou remoção de arquivos locais (LFI). | ✓ | ✓ | ✓ | 73 |
| **12.3.3** | Verificar que metadados de nome de arquivo submetidos pelo usuário são validados ou ignorados para prevenir a revelação ou execução de arquivos remotos via ataques de Remote File Inclusion (RFI) ou de Server-side Request Forgery (SSRF). | ✓ | ✓ | ✓ | 98 |
| **12.3.4** | Verificar que a aplicação protege contra Download e Arquivo Refletido (RFD) ao validar ou ignorar nomes de arquivos submetidos por usuários em um JSON, JSONP, ou parâmetro de URL, o cabeçalho de resposta Content-Type deve ser configurado como text/plain, e o cabeçalho Content-Disposition deve ter um nome fixo. | ✓ | ✓ | ✓ | 641 |
| **12.3.5** | Verificar que metadados de arquivos não confiáveis não são usados diiretamente com APIPs do sistema ou bibliotecas, para proteger contra injeção de comandos de SO. | ✓ | ✓ | ✓ | 78 |
| **12.3.6** | Verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution networks, JavaScript libraries, node npm libraries, or server-side DLLs. |  | ✓ | ✓ | 829 |

## V12.4 File Storage Requirements

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.4.1** | Verificar que arquivos obtidos de fontes não confiáveis são armazenados fora da pasta raiz da web, com permissões limitadas, preferencialmente com forte validação. | ✓ | ✓ | ✓ | 922 |
| **12.4.2** | Verificar que arquivos obtidos de fontes não confiáveis são escaneados pro scanners de antivírus para prevenir o envio de conteúdo malicioso conhecido. | ✓ | ✓ | ✓ | 509 |

## V12.5 File Download Requirements

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.5.1** | Verificar que a camada web está configurada para servir apenas arquivos com extensões de arquivo específicas para prevenir o vazamento não intencional de informações ou código fonte. Por exemplo, arquivos de backup (e.g. .bak), arquivos temporários (e.g. .swp), arquivos comprimidos (.zip, .tar.gz, etc) e outras extensões comumente utilizadas por editores devem ser bloqueadas a não ser que sejam requeridas. | ✓ | ✓ | ✓ | 552 |
| **12.5.2** | Verificar que requisições diretas a arquivos enviados nunca são executadas como conteúdo HTML/JavaScript. | ✓ | ✓ | ✓ | 434 |

## V12.6 SSRF Protection Requirements

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---:| :---: | :---: |
| **12.6.1** | Verificar que o servidor web ou de aplicação está configurado com uma lista de recursos e sistemas para o qual o servidor pode enviar requisições ou do qual ele pode carregar dados de arquivos. | ✓ | ✓ | ✓ | 918 |

## References

For more information, see also:

* [File Extension Handling for Sensitive Information](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
* [Reflective file download by Oren Hafif](https://www.trustwave.com/Resources/SpiderLabs-Blog/Reflected-File-Download---A-New-Web-Attack-Vector/)
* [OWASP Third Party JavaScript Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
