import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"src"))
from zero_trust import AccessContext, decide

def test_allow():
    assert decide(AccessContext(0.05, 0.99, True, 0.0, False))["decision"]=="ALLOW"

def test_deny_priv_no_mfa():
    assert decide(AccessContext(0.1, 0.9, False, 0.0, True))["decision"]=="DENY"

if __name__=="__main__":
    test_allow(); test_deny_priv_no_mfa(); print("ok")
