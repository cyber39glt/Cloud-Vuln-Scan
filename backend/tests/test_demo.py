import json

from app.demo import main


def test_demo_prints_summary(capsys):
    main([])
    out = capsys.readouterr().out
    assert "NET-001" in out
    assert "Not evaluated in us-east-1" in out


def test_demo_json_is_the_full_dataset(capsys):
    main(["--json"])
    datasets = json.loads(capsys.readouterr().out)
    assert [d["provider"] for d in datasets] == ["aws", "azure"]
    assert all(d["findings"] for d in datasets)
