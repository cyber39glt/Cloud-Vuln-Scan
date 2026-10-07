"""Publish the JSON Schema of the JSON export, for anyone integrating with it.

    python -m app.reporting.schema      regenerate backend/schemas/assessment-report.schema.json

A test fails if the committed schema no longer matches the report model, so the
published contract can never silently drift from what the platform produces.
"""

import json
from pathlib import Path

from app.reporting.report import REPORT_SCHEMA_VERSION, AssessmentReport

SCHEMA_PATH = Path(__file__).parents[2] / "schemas" / "assessment-report.schema.json"


def report_json_schema() -> dict:
    schema = AssessmentReport.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = f"Cloud Vuln Scan assessment report v{REPORT_SCHEMA_VERSION}"
    return schema


def render_schema() -> str:
    return json.dumps(report_json_schema(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    SCHEMA_PATH.parent.mkdir(exist_ok=True)
    SCHEMA_PATH.write_text(render_schema(), encoding="utf-8")
    print(f"Written: {SCHEMA_PATH}")
