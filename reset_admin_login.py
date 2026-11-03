"""Compatibility alias for the documented offline MFA recovery command."""
import sys

from database import reset_admin_mfa


def main() -> None:
    if len(sys.argv) != 2:
        print("Uso: python reset_admin_login.py <email_do_administrador>")
        raise SystemExit(1)
    email = sys.argv[1].strip()
    if not reset_admin_mfa(email):
        print("Administrador não encontrado.")
        raise SystemExit(1)
    print("MFA reinicializado e sessões revogadas. Configure o autenticador no próximo login.")


if __name__ == "__main__":
    main()
