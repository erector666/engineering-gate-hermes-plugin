import sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"engineering-gate"))
from reviewer_service.service import Ledger

def test_cost_cap_and_daily_review_cap_fail_closed(tmp_path):
    ledger=Ledger(tmp_path/"quota.sqlite")
    for index in range(2): ledger.reserve(f"{index:032x}","r","p","a")
    with pytest.raises(Exception): ledger.reserve("f"*32,"r","p","a")
    assert ledger.db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]==2
    assert ledger.db.execute("SELECT SUM(reserved) FROM reviews").fetchone()[0] > 1.0

def test_quota_configuration_is_bounded_and_rejects_nonfinite_budget(tmp_path):
    with pytest.raises(ValueError): Ledger(tmp_path/"nan.sqlite",daily_budget_usd=float("nan"))
    ledger=Ledger(tmp_path/"custom.sqlite",max_reviews_per_day=1,daily_budget_usd=10)
    ledger.reserve("a"*32,"r","p","a")
    with pytest.raises(Exception): ledger.reserve("b"*32,"r","p","a")
