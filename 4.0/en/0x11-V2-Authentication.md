# V2: Requerimentos de Verificação de Autenticação

## Objetivo do Controle

Autenticação é o ato de estabelecer ou confirmar, alguma pessoa (ou alguma coisa) como autêntica e que reivindicações feitas por uma pessoa ou sobre um dispositivo são corretas, resistentes a impersonação e previnem recuperação ou interceptação de senhas.

Quando o ASVS foi lançado pela primeira vez, nome de usuário + senha era a forma mais comum de autenticação fora de sistemas de segurança elevada. Autenticação Multi-fator (AMF) era comumente aceita em círculos de segurança, mas raramente requerida em outros lugares. Como o número de vazamentos de senha aumentou, a ideia de que nomes de usuário são, de alguma forma, confidenciais e senhas desconhecidas, deixou muitos controles de segurança insustentáveis. Por exemplo, a NIST 800-63 considera nomes de usuário e autenticação baseada no conhecimento como informação pública, notificações por SMS e e-mail como [tipos de autenticadores "restritos"](https://pages.nist.gov/800-63-FAQ/#q-b1) , e senhas como pré-vazadas. Esta realidade deixa autenticadores baseados em conhecimento, recuperação por SMS e email, histórico de senhas, complexidade e controles de rotações inúteis. Esses controles sempre foram menos do que úteis, frequentemente forçando usuários a criar senhas fracas a cada poucos meses, mas com a revelação de mais de 5 bilhões de usuários e senhas vazados, é hora de seguir em frente.

De todos os capítulos do ASVS, os capítulos de autenticação e gerenciamento de sessão foram os que mais mudaram. A adoção de práticas efetivas guiadas com base em evidências vai ser desafiadora para muitos e isso é perfeitamente normal. Nós temos que iniciar a transição para um futuro pós-senhas agora.

## NIST 800-63 - Padrão de autenticação moderno e baseado em evidências

A [NIST 800-63b](https://pages.nist.gov/800-63-3/sp800-63b.html) é um padrão moderno baseado em evidências e representa a melhor recomendação disponível, independentemente da aplicabilidade. O padrão é útil para todas as organizações em todo o mundo, mas é particularmente relevante para as agências dos EUA e para aqueles lidando com as agências dos EUA.

A terminologia da NIST 800-63 pode ser um pouco confusa no início, especialmente se você está familiarizado apenas com autenticação usuário + senha. Avanços na autenticação moderna são necessários, então temos que introduzir uma terminologia que vai se tornar comum no futuro, mas nós entendemos a dificuldade no entendimento até que a indústria estabeleça esses novos termos. Nós providenciamos um glossário no fim deste capítulo para auxiliar. Nós reformulamos muitos requerimentos para satisfazer a intenção do requerimento, ao invés ~da letra~ do requerimento. Por exemplo, o ASVS usa o termo "senha" através deste padrão, enquanto a NIST usa "segredos memorizados".

ASVS V2 Autenticação, V3 Gerenciamento de Sessão e, em menor grau, V4 Controle de Acesso foram adaptados para estarem em conformidade com um subconjunto de controles selecionados da NIST 800-63b, focados em torno de ameaças comuns e fraquezas de autenticação comumente exploradas. Onde conformidade total com a NIST 800-63 é requerida, por favor, consulte a NIST 800-63.

### Selecionando um nível NIST AAL apropriado

O Padrão de Verificação de Segurança de Aplicações tentou mapear as exigências ASVS L1 para as da NIST AAL1, L2 para AAL2, e L3 para AAL3. No entanto, a abordagem do Nível 1 do ASVS como controles "essenciais" pode não ser necessariamente os nível AAL correto para verificar uma aplicação ou API. Por exemplo, se a aplicação é uma aplicação de Nível 3 ou possui requerimentos regulatórios para ser AAL3, Nível 3 deve ser escolhido nos capítulos V2 e V3 Gerenciamento de Sessão. A escolher de Nível de Afirmação de Autenticação (AAL) deve ser realizada conforme as diretrizes da NIST 800-63b como estabelecido em *Selecionando o AAL* em [NIST 800-63b Section 6.2](https://pages.nist.gov/800-63-3/sp800-63-3.html#AAL_CYOA).

## Legenda

Aplicações podem sempre exceder o nível atual de requerimentos, especialmente se autenticação moderna está no roteiro da aplicação. Previamente, o ASVS requereu AMF mandatória. A NIST não requer AMF mandatória. Portanto, nós usamos uma designação especial neste capítulo para indicar onde o ASVS encoraja, mas não requer um controle. As chaves seguintes são utilizadas através deste padrão:

| símbolo | Descrição |
| :--: | :-- |
| | Não requerido |
| o | Recomendado, mas não requerido |
| ✓ | Requerido |

## V2.1 Requerimentos de Segurança de Senhas

Senhas, chamadas de "Segredos Memorizados" pela NIST 800-63, incluem senhas, PINs, padrões de desbloqueio, escolha o gatinho correto ou outro elemento de imagem e frases-passe. Eles são geralmente considerados "algo que você sabe" e muitas vezes são usados como autenticadores de fator único. Existem desafios significativos para a continuidade destes autenticadores de fator único, incluindo bilhões de usuários e senhas válidos vazados na Internet, senhas fracas ou padrão,  
Passwords, called "Memorized Secrets" by NIST 800-63, include passwords, PINs, unlock patterns, pick the correct kitten or another image element, and passphrases. They are generally considered "something you know", and often used as single-factor authenticators. There are significant challenges to the continued use of single-factor authentication, including billions of valid usernames and passwords disclosed on the Internet, default or weak passwords, tabelas arco-íris e dicionários ordenados das senhas mais comuns.

Aplicações devem encorajar fortemente os usuários a se cadastrar na autenticação multi-fator, e devem permitir que esses usuários reusem tokens que eles já possuem, como os tokens FIDO ou U2F, ou conectar a um provedor de serviços de credenciais que provê autenticação multi-fator.

Provedores de Serciços de Credenciais (CSPs) proveem identidade federada para usuários. Usuários frequentemente ter mais de uma identidade em múltiplos CSPs, como uma identidade empresarial usando Azure AD, Okta, Ping Identify ou Google, ou identidade de consumidor usando Facebook, Twiter, Google, ou WeChat, para nomear apenas algumas alternativas comuns. Esta lista não é um endosso a essas companhias ou serviços, mas simplesmente um encorajamento para desenvolvedores considerarem a realidade que muitos usuários tem muitas identidades estabelecidas. Organizações devem considerar integração com identidades de usuário existentes, conforme o perfil de risco da força da prova de identidade do CSP. Por exemplo, é improvável que uma organização governamental iria aceitar uma identidade de mídia social como login para sistemas sensíveis, pois é fácil criar identidades falsas ou destruí-las, enquanto uma empresa de jogos de celular pode muito bem precisar de se integrar a grandes plataformas de mídias sociais para aumentar sua base de jogadores ativos.

| # | Descrição | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.1.1** | Verificar que as senhas de usuários possuem ao menos 12 caracteres de tamanho (após múltiplos espaços em branco serem combinados). ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |
| **2.1.2** | Verificar que senhas com 64 caracteres ou mais são permitidos, mas não devem ser maiores que 128 caracteres. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |
| **2.1.3** | Verificar que truncagem de senha não é realizada. No entanto, múltiplos espaços em branco consecutivos podem ser substituídos por um único espaço em branco. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |
| **2.1.4** | Verificar que qualquer caractere Unicode imprimível, incluindo caracteres de linguagem neutra como espaços em branco e Emojis são permitidos em senhas. | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |
| **2.1.5** | Verificar que usuários podem alterar sua senha. | ✓ | ✓ | ✓ | 620 | 5.1.1.2 |
| **2.1.6** | Verificar que a funcionalidade de alteração de senha requer a senha atual e a nova senha do usuário. | ✓ | ✓ | ✓ | 620 | 5.1.1.2 |
| **2.1.7** | Verificar que senhas submetidas durante registro de conta, login, e troca de senha são checadas contra um conjunto de senhas vazadas feito localmente (como as 1.000 ou 10.000 senhas mais comuns que correspondem à política de senha do sistema) ou usando uma API externa. Se uma API for usada, uma prova de conhecimento-zero ou outro mecanismo deve ser usado para garantir que senhas em texto plano não são enviadas ou usadas na verificação do estado de vazado da senha. Se a senha foi vazada, a aplicação deve requerer que o usuário configure uma nova senha não vazada. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |
| **2.1.8** | Verificar que um medidor de força de senha é provido para ajudar os usuários a escolherem uma senha mais forte. | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |
| **2.1.9** | Verificar que não há regras de composição de senhas limitando os tipos de caracteres permitidos. Não deve haver requerimento para letras maiúsculas e minúsculas ou números ou caracteres especiais. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |
| **2.1.10** | Verificar que não há rotação periódica de credenciais ou requerimento de histórico de senhas. | ✓ | ✓ | ✓ | 263 | 5.1.1.2 |
| **2.1.11** | Verificar que a funcionalidade de "colar", preenchimento automático de senhas em navegadores e gerenciadores de senha externos são permitidos. | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |
| **2.1.12** | Verificar que o usuário pode escolher entre ver temporariamente a senha inteira mascarada ou ver temporariamente o último caractere digitado da senha em plataformas que não possuem essa funcionalidade embutida. | ✓ | ✓ | ✓ | 521 | 5.1.1.2 |

Nota: O objetivo de permitir que o usuário veja sua senha ou veja o último caractere temporariamente é melhorar a usabilidade do registro de credenciais, particularmente em torno do uso de senhas mais longas, frases-passe e gerenciadores de senhas. Outra razão para incluir o requerimento é para deter ou prevenir relatórios de teste desnecessariamente requerendo que organizações sobreponham o comportamento padrão do campo de senha da plataforma para remover essa moderna experiência de segurança amigável ao usuário.

## V2.2 Requerimentos de Autenticador Gerais
 
Authenticator agility is essential to future-proof applications. Refactor application verifiers to allow additional authenticators as per user preferences, as well as allowing retiring deprecated or unsafe authenticators in an orderly fashion.

NIST considers email and SMS as ["restricted" authenticator types](https://pages.nist.gov/800-63-FAQ/#q-b1), and they are likely to be removed from NIST 800-63 and thus the ASVS at some point the future. Applications should plan a roadmap that does not require the use of email or SMS.

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.2.1** | Verificar que controles de anti-automação são efetivos em mitigar ataques de testes de credenciais vazadas, força bruta e bloqueio de conta.Tais controles incluem bloquear as senhas vazadas mais comuns, bloqueios suaves, limitação de taxa de solicitações, CAPTCHA, demoras sempre crescentes entre tentativas, restrições de IP, ou restrições baseadas em risco, como local, primeiro login em um dispositivo, tentativas recentes de desbloquear uma conta ou similares. Verificar que não mais do que 100 tentativas falhas por hora são possíveis em uma única conta.  | ✓ | ✓ | ✓ | 307 | 5.2.2 / 5.1.1.2 / 5.1.4.2 / 5.1.5.2 |
| **2.2.2** | Verificar que o uso de autenticadores fracos (como SMS e email) são limitados a verificações secundárias ou aprovação de transações e não como substitutos para métodos de autenticação mais seguros. Verificar que métodos mais seguros são oferecidos antes de métodos menos seguros, que os usuários estão conscientes dos riscos, ou que medidas cabíveis estão em vigor para limitar o risco de comprometimento de contas.
 | ✓ | ✓ | ✓ | 304 | 5.2.10 |
| **2.2.3** | Verificar que notificações seguras são enviadas aos usuários depois de atualizações de detalhes de autenticação, como redefinições de credenciais, mudanças de email ou endereço, login de locais desconhecidos ou perigosos. O uso de notificações push - ao invés de SMS ou email - é preferível, mas na ausência de notificações push, SMS ou email são aceitáveis quando informações sensíveis não são reveladas na notificação. | ✓ | ✓ | ✓ | 620 | |
| **2.2.4** | Verify impersonation resistance against phishing, such as the use of multi-factor authentication, cryptographic devices with intent (such as connected keys with a push to authenticate), or at higher AAL levels, client-side certificates. |  |  | ✓ | 308 | 5.2.5 |
| **2.2.5** | Verify that where a Credential Service Provider (CSP) and the application verifying authentication are separated, mutually authenticated TLS is in place between the two endpoints. |  |  | ✓ | 319 | 5.2.6 |
| **2.2.6** | Verify replay resistance through the mandated use of One-time Passwords (OTP) devices, cryptographic authenticators, or lookup codes. |  |  | ✓ | 308 | 5.2.8 |
| **2.2.7** | Verify intent to authenticate by requiring the entry of an OTP token or user-initiated action such as a button press on a FIDO hardware key. |  |  | ✓ | 308 | 5.2.9 |

## V2.3 Authenticator Lifecycle Requirements

Authenticators are passwords, soft tokens, hardware tokens, and biometric devices. The lifecycle of authenticators is critical to the security of an application - if anyone can self-register an account with no evidence of identity, there can be little trust in the identity assertion. For social media sites like Reddit, that's perfectly okay. For banking systems, a greater focus on the registration and issuance of credentials and devices is critical to the security of the application.

Note: Passwords are not to have a maximum lifetime or be subject to password rotation. Passwords should be checked for being breached, not regularly replaced.

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.3.1** | Verificar que senhas iniciais ou códigos de ativação gerados pelo sistema devem ser gerados randomicamente de forma segura, devem ter no mínimo 6 caracteres e podem conter letras e números, e expirar após um curto período de tempo. Não deve ser permitido que estes segredos iniciais se torne a senha de longo prazo. | ✓ | ✓ | ✓ | 330 | 5.1.1.2 / A.3 |
| **2.3.2** | Verify that enrollment and use of subscriber-provided authentication devices are supported, such as a U2F or FIDO tokens. |  | ✓ | ✓ | 308 | 6.1.3 |
| **2.3.3** | Verify that renewal instructions are sent with sufficient time to renew time bound authenticators. |  | ✓ | ✓ | 287 | 6.1.4 |

## V2.4 Credential Storage Requirements

Architects and developers should adhere to this section when building or refactoring code. This section can only be fully verified using source code review or through  secure unit or integration tests. Penetration testing cannot identify any of these issues.

The list of approved one-way key derivation functions is detailed in NIST 800-63 B section 5.1.1.2, and in [BSI Kryptographische Verfahren: Empfehlungen und Schlussell&auml;ngen (2018)](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf?__blob=publicationFile). The latest national or regional algorithm and key length standards can be chosen in place of these choices.

This section cannot be penetration tested, so controls are not marked as L1. However, this section is of vital importance to the security of credentials if they are stolen, so if forking the ASVS for an architecture or coding guideline or source code review checklist, please place these controls back to L1 in your private version.

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.4.1** | Verify that passwords are stored in a form that is resistant to offline attacks. Passwords SHALL be salted and hashed using an approved one-way key derivation or password hashing function. Key derivation and password hashing functions take a password, a salt, and a cost factor as inputs when generating a password hash. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 916 | 5.1.1.2 |
| **2.4.2** | Verify that the salt is at least 32 bits in length and be chosen arbitrarily to minimize salt value collisions among stored hashes. For each credential, a unique salt value and the resulting hash SHALL be stored. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 916 | 5.1.1.2 |
| **2.4.3** | Verify that if PBKDF2 is used, the iteration count SHOULD be as large as verification server performance will allow, typically at least 100,000 iterations. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 916 | 5.1.1.2 |
| **2.4.4** | Verify that if bcrypt is used, the work factor SHOULD be as large as verification server performance will allow, typically at least 13. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 916 | 5.1.1.2 |
| **2.4.5** | Verify that an additional iteration of a key derivation function is performed, using a salt value that is secret and known only to the verifier. Generate the salt value using an approved random bit generator [SP 800-90Ar1] and provide at least the minimum security strength specified in the latest revision of SP 800-131A. The secret salt value SHALL be stored separately from the hashed passwords (e.g., in a specialized device like a hardware security module). |  | ✓ | ✓ | 916 | 5.1.1.2 |

Where US standards are mentioned, a regional or local standard can be used in place of or in addition to the US standard as required.

## V2.5 Credential Recovery Requirements

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.5.1** | [MODIFIED] Verificar que se uma ativação inicial ou segredo de recuperação gerada pelo sistema é enviado para o usuário, ele deve ser de uso único, com tempo limitado e aleatório. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 640 | 5.1.1.2 |
| **2.5.2** | Verificar que dicas de senha ou autenticação baseada em conhecimento (as chamadas "perguntas secretas") não estão presentes. | ✓ | ✓ | ✓ | 640 | 5.1.1.2 |
| **2.5.3** | Verificar que a recuperação de senha não revela a senha atual de qualquer maneira. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 640 | 5.1.1.2 |
| **2.5.4** | Verificar que contas compartilhadas ou padrão não estão presentes (e.g. "root", "admin", ou "sa"). | ✓ | ✓ | ✓ | 16 | 5.1.1.2 / A.3 |
| **2.5.5** | Verificar que se um fator de autenticação é alterado ou trocado, o usuário é notificado deste evento. | ✓ | ✓ | ✓ | 304 | 6.1.2.3 |
| **2.5.6** | **Verificar que "esqueci a senha" ou outro caminho de recuperação usam um mecanismo de recuperação seguro, como OTP baseado em tempo (TOTP) ou outro token de software, notificações push móveis, ou outro método de recuperação offline. ???**
Verify forgotten password, and other recovery paths use a secure recovery mechanism, such as time-based OTP (TOTP) or other soft token, mobile push, or another offline recovery mechanism. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 640 | 5.1.1.2 |
| **2.5.7** | Verify that if OTP or multi-factor authentication factors are lost, that evidence of identity proofing is performed at the same level as during enrollment. |  | ✓ | ✓ | 308 | 6.1.2.3 |

## V2.6 Look-up Secret Verifier Requirements

Look up secrets are pre-generated lists of secret codes, similar to Transaction Authorization Numbers (TAN), social media recovery codes, or a grid containing a set of random values. These are distributed securely to users. These lookup codes are used once, and once all used, the lookup secret list is discarded. This type of authenticator is considered "something you have".

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.6.1** | Verify that lookup secrets can be used only once. |  | ✓ | ✓ | 308 | 5.1.2.2 |
| **2.6.2** | Verify that lookup secrets have sufficient randomness (112 bits of entropy), or if less than 112 bits of entropy, salted with a unique and random 32-bit salt and hashed with an approved one-way hash. |  | ✓ | ✓ | 330 | 5.1.2.2 |
| **2.6.3** | Verify that lookup secrets are resistant to offline attacks, such as predictable values. |  | ✓ | ✓ | 310 | 5.1.2.2 |

## V2.7 Out of Band Verifier Requirements

In the past, a common out of band verifier would have been an email or SMS containing a password reset link. Attackers use this weak mechanism to reset accounts they don't yet control, such as taking over a person's email account and re-using any discovered reset links. There are better ways to handle out of band verification.

Secure out of band authenticators are physical devices that can communicate with the verifier over a secure secondary channel. Examples include push notifications to mobile devices. This type of authenticator is considered "something you have". When a user wishes to authenticate, the verifying application sends a message to the out of band authenticator via a connection to the authenticator directly or indirectly through a third party service. The message contains an authentication code (typically a random six digit number or a modal approval dialog). The verifying application waits to receive the authentication code through the primary channel and compares the hash of the received value to the hash of the original authentication code. If they match, the out of band verifier can assume that the user has authenticated.

The ASVS assumes that only a few developers will be developing new out of band authenticators, such as push notifications, and thus the following ASVS controls apply to verifiers, such as authentication API, applications, and single sign-on implementations. If developing a new out of band authenticator, please refer to NIST 800-63B &sect; 5.1.3.1.

Unsafe out of band authenticators such as e-mail and VOIP are not permitted. PSTN and SMS authentication are currently "restricted" by NIST and should be deprecated in favor of push notifications or similar. If you need to use telephone or SMS out of band authentication, please see &sect; 5.1.3.3.

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.7.1** | Verificar que autenticadores fora de banda em texto plano ("restritos" pela NIST), como SMS ou PSTN, não são oferecidos por padrão e alternativas mais fortes como notificações push são oferecidas primeiro. | ✓ | ✓ | ✓ | 287 | 5.1.3.2 |
| **2.7.2** | Verificar que verificadores fora de banda expiram requisições de autenticação, códigos e tokens fora de banda após 10 minutos. | ✓ | ✓ | ✓ | 287 | 5.1.3.2 |
| **2.7.3** | Verificar que requisições de autenticação, códigosou tokens foram de banda são usáveis apenas uma vez e apenas para a requisição de autenticação original. | ✓ | ✓ | ✓ | 287 | 5.1.3.2 |
| **2.7.4** | Verificar que autenticadores e verificadores foram de banda se comunicam através de um canal seguro independente. | ✓ | ✓ | ✓ | 523 | 5.1.3.2 |
| **2.7.5** | Verify that the out of band verifier retains only a hashed version of the authentication code. |  | ✓ | ✓ | 256 | 5.1.3.2 |
| **2.7.6** | Verify that the initial authentication code is generated by a secure random number generator, containing at least 20 bits of entropy (typically a six digital random number is sufficient). |  | ✓ | ✓ | 310 | 5.1.3.2 |

## V2.8 Single or Multi-factor One Time Verifier Requirements

Single-factor One-time Passwords (OTPs) are physical or soft tokens that display a continually changing pseudo-random one-time challenge. These devices make phishing (impersonation) difficult, but not impossible. This type of authenticator is considered "something you have". Multi-factor tokens are similar to single-factor OTPs, but require a valid PIN code, biometric unlocking, USB insertion or NFC pairing or some additional value (such as transaction signing calculators) to be entered to create the final OTP.

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.8.1** | Verificar que OTPs baseados em tempo tem um tempo de vida definido antes de expirar. | ✓ | ✓ | ✓ | 613 | 5.1.4.2 / 5.1.5.2 |
| **2.8.2** | Verify that symmetric keys used to verify submitted OTPs are highly protected, such as by using a hardware security module or secure operating system based key storage. |  | ✓ | ✓ | 320 | 5.1.4.2 / 5.1.5.2|
| **2.8.3** | Verify that approved cryptographic algorithms are used in the generation, seeding, and verification of OTPs. |  | ✓ | ✓ | 326 | 5.1.4.2 / 5.1.5.2 |
| **2.8.4** | Verify that time-based OTP can be used only once within the validity period. |  | ✓ | ✓ | 287 | 5.1.4.2 / 5.1.5.2 |
| **2.8.5** | Verify that if a time-based multi-factor OTP token is re-used during the validity period, it is logged and rejected with secure notifications being sent to the holder of the device. |  | ✓ | ✓ | 287 | 5.1.5.2 |
| **2.8.6** | Verify physical single-factor OTP generator can be revoked in case of theft or other loss. Ensure that revocation is immediately effective across logged in sessions, regardless of location. |  | ✓ | ✓ | 613 | 5.2.1 |
| **2.8.7** | Verify that biometric authenticators are limited to use only as secondary factors in conjunction with either something you have and something you know. |  | o | ✓ | 308 | 5.2.3 |

## V2.9 Cryptographic Software and Devices Verifier Requirements

Cryptographic security keys are smart cards or FIDO keys, where the user has to plug in or pair the cryptographic device to the computer to complete authentication. Verifiers send a challenge nonce to the cryptographic devices or software, and the device or software calculates a response based upon a securely stored cryptographic key.

The requirements for single-factor cryptographic devices and software, and multi-factor cryptographic devices and software are the same, as verification of the cryptographic authenticator proves possession of the authentication factor.

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.9.1** | Verify that cryptographic keys used in verification are stored securely and protected against disclosure, such as using a Trusted Platform Module (TPM) or Hardware Security Module (HSM), or an OS service that can use this secure storage. |  | ✓ | ✓ | 320 | 5.1.7.2 |
| **2.9.2** | [L2>L3] Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device. |  |  | ✓ | 330 | 5.1.7.2 |
| **2.9.3** | Verify that approved cryptographic algorithms are used in the generation, seeding, and verification. | | ✓ | ✓ | 327 | 5.1.7.2 |

## V2.10 Service Authentication Requirements

This section is not penetration testable, so does not have any L1 requirements. However, if used in an architecture, coding or secure code review, please assume that software (just as Java Key Store) is the minimum requirement at L1. Clear text storage of secrets is not acceptable under any circumstances.

| # | Description | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **2.10.1** | Verify that intra-service secrets do not rely on unchanging credentials such as passwords, API keys or shared accounts with privileged access. |  | OS assisted | HSM | 287 | 5.1.1.1 |
| **2.10.2** | Verify that if passwords are required for service authentication, the service account used is not a default credential. (e.g. root/root or admin/admin are default in some services during installation). |  | OS assisted | HSM | 255 | 5.1.1.1 |
| **2.10.3** | Verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access. |  | OS assisted | HSM | 522 | 5.1.1.1 |
| **2.10.4** | Verify passwords, integrations with databases and third-party systems, seeds and internal secrets, and API keys are managed securely and not included in the source code or stored within source code repositories. Such storage SHOULD resist offline attacks. The use of a secure software key store (L1), hardware TPM, or an HSM (L3) is recommended for password storage. |  | OS assisted | HSM | 798 | |

## Requerimientos Adicionais para agências dos EUA

Agências dos EUA possuem requerimentos mandatórios relativos à NIST 800-63. O Padrão de Verificação de Segurança de Aplicações sempre foi sobre os 80% dos controles que se aplicam a aproximadamente 100% das aplicações e não os 20% restantes dos controles avançados ou aqueles que tem aplicabilidade limitada. Assim sendo, o ASVS é um subconjunto estrito da NIST 800-63, especialmente para as classificações IAL1/2 e AAL1/2, mas não é suficientemente completo, particularmente a respeito das classificações IAL3/AAL3.

Nós fortemente recomendamos às agências governamentais dos EUA a revisar e implementar a NIST 800-63 inteiramente.

## Glossary of terms

| Termo | Significado |
| -- | -- |
| CSP | Credential Service Provider also called an Identity Provider |
| Autenticador | Code that authenticates a password, token, MFA, federated assertion, and so on. |
| Verificador | "An entity that verifies the claimant's identity by verifying the claimant's possession and control of one or two authenticators using an authentication protocol. To do this, the verifier may also need to validate credentials that link the authenticator(s) to the subscriber's identifier and check their status" |
| OTP | One-time password |
| SFA | Single-factor authenticators, such as something you know (memorized secrets, passwords, passphrases, PINs), something you are (biometrics, fingerprint, face scans), or something you have (OTP tokens, a cryptographic device such as a smart card),  |
| MFA | Multi-factor authentication, which includes two or more single factors |

## Referências

Para mais informações, veja também:

* [NIST 800-63 - Digital Identity Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf)
* [NIST 800-63 A - Enrollment and Identity Proofing](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63a.pdf)
* [NIST 800-63 B - Authentication and Lifecycle Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf)
* [NIST 800-63 C - Federation and Assertions](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63c.pdf)
* [NIST 800-63 FAQ](https://pages.nist.gov/800-63-FAQ/)
* [OWASP Testing Guide 4.0: Testing for Authentication](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/04-Authentication_Testing/README.html)
* [OWASP Cheat Sheet - Password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet - Forgot password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
* [OWASP Cheat Sheet - Choosing and using security questions](https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html)
