#!/usr/bin/env python3
"""
Script de recuperação administrativa presencial / fora de banda.
Permite ao administrador do servidor repor a autenticação multifator (MFA TOTP)
de uma conta de administrador sem qualquer bypass público no site.

Uso:
    python reset_admin_mfa.py <email_do_administrador>
"""
import sys
from database import reset_admin_mfa

def main():
    if len(sys.argv) < 2:
        print("Uso: python reset_admin_mfa.py <email_do_administrador>")
        sys.exit(1)

    target_email = sys.argv[1].strip()
    if reset_admin_mfa(target_email):
        print(f"[OK] MFA reinicializado com sucesso para o administrador: {target_email}")
        print("No próximo início de sessão, será solicitada uma nova configuração do autenticador TOTP.")
    else:
        print(f"[ERRO] Administrador não encontrado ou não possui perfil ADMIN: {target_email}")
        sys.exit(1)

if __name__ == '__main__':
    main()
