"""Run the rule engine on the sample inventories and print the outcome.

    python -m app.demo                      human-readable summary
    python -m app.demo --json               the full AssessmentResult datasets as JSON
    python -m app.demo --save "Demo Client" store the AWS sample as a clearly labelled
                                            demo assessment, to try listing and exports

No cloud access: the input is app/sample_data.py.
"""

import argparse
import json

from app.console import UNVERIFIED_NOTE, format_summary
from app.core.config import get_settings
from app.core.database import get_sessionmaker
from app.rules.engine import RuleEngine
from app.sample_data import AWS_ACCOUNT, sample_aws_inventory, sample_azure_inventory
from app.storage import repository as repo

DEMO_ASSESSMENT_NAME = "SAMPLE DATA - not a real scan"


def save_demo(client_name: str) -> str:
    """Store the AWS sample result under `client_name`; returns the scan ID."""
    result = RuleEngine().run(sample_aws_inventory())
    with get_sessionmaker().begin() as db:
        try:
            client = repo.find_client(db, client_name)
        except repo.NotFoundError:
            client = repo.create_client(db, client_name)
        connection = repo.get_or_create_aws_connection(
            db, client.id, AWS_ACCOUNT, get_settings().consultancy_name
        )
        assessment = repo.get_or_create_assessment(
            db, client.id, connection.id, DEMO_ASSESSMENT_NAME
        )
        return str(repo.save_scan_result(db, client.id, assessment.id, result).id)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print full JSON datasets")
    parser.add_argument("--save", metavar="CLIENT", help="store the AWS sample for a client")
    args = parser.parse_args(argv)

    if args.save:
        scan_id = save_demo(args.save)
        print(f'Sample data saved for "{args.save}" as scan {scan_id}')
        print(f'(assessment "{DEMO_ASSESSMENT_NAME}"). Try:')
        print(f'  assessments export --client "{args.save}" --scan {scan_id}')
        return

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
