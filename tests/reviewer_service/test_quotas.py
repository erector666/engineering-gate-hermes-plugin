import sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"engineering-gate"))
from reviewer_service.service import Ledger

LEDGER_CONFIG={"max_reviews_per_day":2,"daily_budget_usd":1.25,
               "input_price_per_million_usd":2.0,"output_price_per_million_usd":10.0,
               "max_output_tokens":2048}

def configured_ledger(path, **overrides):
    return Ledger(path, **(LEDGER_CONFIG | overrides))

def test_cost_cap_and_daily_review_cap_fail_closed(tmp_path):
    ledger=configured_ledger(tmp_path/"quota.sqlite")
    for index in range(2): ledger.reserve(f"{index:032x}","r","p","a")
    with pytest.raises(Exception): ledger.reserve("f"*32,"r","p","a")
    assert ledger.db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]==2
    assert ledger.db.execute("SELECT SUM(reserved) FROM reviews").fetchone()[0] > 1.0

def test_quota_configuration_is_bounded_and_rejects_nonfinite_budget(tmp_path):
    with pytest.raises(ValueError): configured_ledger(tmp_path/"nan.sqlite",daily_budget_usd=float("nan"))
    ledger=configured_ledger(tmp_path/"custom.sqlite",max_reviews_per_day=1,daily_budget_usd=10)
    ledger.reserve("a"*32,"r","p","a")
    with pytest.raises(Exception): ledger.reserve("b"*32,"r","p","a")

@pytest.mark.parametrize("field,value", [
    ("max_reviews_per_day", 0), ("max_reviews_per_day", True),
    ("daily_budget_usd", 0), ("daily_budget_usd", -1), ("daily_budget_usd", True),
    ("daily_budget_usd", "1"), ("daily_budget_usd", float("nan")),
    ("daily_budget_usd", float("inf")), pytest.param("daily_budget_usd", 10**10000, id="huge-budget-int"),
    ("input_price_per_million_usd", -1), ("input_price_per_million_usd", True),
    ("input_price_per_million_usd", "1"), ("input_price_per_million_usd", float("nan")),
    ("input_price_per_million_usd", float("inf")), pytest.param("input_price_per_million_usd", 10**10000, id="huge-input-price-int"),
    ("output_price_per_million_usd", -1), ("output_price_per_million_usd", True),
    ("output_price_per_million_usd", "1"), ("output_price_per_million_usd", float("nan")),
    ("output_price_per_million_usd", float("inf")), pytest.param("output_price_per_million_usd", 10**10000, id="huge-output-price-int"),
    ("max_output_tokens", 0), ("max_output_tokens", 2049),
    ("max_output_tokens", True), ("max_output_tokens", 1.0), ("max_output_tokens", "1"),
])
def test_invalid_quota_config_is_rejected_before_filesystem_changes(tmp_path, field, value):
    parent=tmp_path/"not-created"
    with pytest.raises(ValueError): configured_ledger(parent/"ledger.sqlite", **{field:value})
    assert not parent.exists()

def test_zero_prices_are_valid_for_free_adapters(tmp_path):
    ledger=configured_ledger(tmp_path/"free.sqlite",input_price_per_million_usd=0,output_price_per_million_usd=0)
    assert ledger.input_price == ledger.output_price == 0
