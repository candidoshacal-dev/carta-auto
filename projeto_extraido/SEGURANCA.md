# Segurança Carta Auto Testes

## Estado de MFA

A autenticação TOTP está implementada para todas as contas ADMIN. Uma password correta, sem o segundo fator, não cria uma sessão administrativa. No primeiro login, o admin recebe um token temporário de configuração, associa a chave a uma aplicação autenticadora e confirma o primeiro código.

- TOTP usa a biblioteca pyotp e a norma RFC 6238.
- O segredo fica cifrado com Fernet; usa CAT_MFA_ENCRYPTION_KEY quando definida, ou uma chave derivada de SESSION_SECRET.
- Os códigos de recuperação são aleatórios, armazenados como hashes e consumidos uma única vez.
- Códigos TOTP são comparados em tempo constante e códigos repetidos são recusados.
- Cinco falhas bloqueiam temporariamente a conta por 15 minutos.
- Logout e alterações de password/permissões revogam sessões por session_version.
- reset_admin_mfa.py é a recuperação administrativa fora de banda e deve ser executado localmente por pessoa autorizada.
- A página mostra a chave TOTP para introdução manual numa aplicação autenticadora; os códigos de recuperação devem ser guardados fora do computador.

## Verificações feitas

Os testes de API em base temporária verificam configuração inicial, ausência de sessão antes do MFA, código inválido, TOTP válido, replay de TOTP, código de recuperação de uso único, revogação de sessão e acesso administrativo.

## Pendências antes de expor o painel

- Definir e guardar SESSION_SECRET, CAT_ADMIN_PASSWORD e, se desejado, CAT_MFA_ENCRYPTION_KEY num gestor de segredos ou no .env de produção, nunca no ZIP/Git.
- Configurar HTTPS e SMTP; validar recuperação de password sem revelar se a conta existe.
- Definir limite de tentativas também por IP/proxy confiável e política de backups cifrados com ensaio de restauro.
- Fazer revisão manual dos restantes endpoints e teste visual/f funcional no browser.
- Trocar a password de demonstração; nunca usar admin123 em produção.

A aplicação ainda não está publicada. Não disponibilizar o painel admin na internet até estas configurações e verificações estarem concluídas.
