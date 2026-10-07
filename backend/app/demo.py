"""Run the rule engine on the sample inventories and print the outcome.

    python -m app.demo          human-readable summary
    python -m app.demo --json   the full AssessmentResult datasets as JSON

No cloud access: the input is app/sample_data.py.
"""

import argparse
import json

from app.console import UNVERIFIED_NOTE, format_summary
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory, sample_azure_inventory


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print full JSON datasets")
    args = parser.parse_args(argv)

    engine = RuleEngine()
    results = [engine.run(sample_aws_inventory()), engine.run(sample_azure_inventory())]

    if args.json:
        print(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
        return
    for result in results:
        print(format_summary(result))
    print(f"\n{UNVERIFIED_NOTE}")


if __name__ == "__main__":
    main()
