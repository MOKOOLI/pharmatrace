from pharmatrace.core.security import Role, TokenSigner
from pharmatrace.core.service import TraceService

GTIN = "05012345678900"  # valid check digit

signer = TokenSigner("test-secret")


def claims(role: Role, org: str, user: str = "u"):
    return signer.verify(signer.issue(user, role, org))


def seeded():
    svc = TraceService()
    reg = claims(Role.REGULATOR, "FDA-IR", "reg")
    mfr = claims(Role.MANUFACTURER, "ACME", "mfr")
    svc.register_drug(mfr, GTIN, "Amoxicillin 500mg")
    svc.approve_drug(reg, GTIN)
    uids = svc.create_units(mfr, GTIN, "LOT1", "2099-12-31", 3)
    return svc, reg, mfr, uids
