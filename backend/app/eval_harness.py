"""Measures whether the AI's own verdicts actually agree with human-confirmed dispositions —
distinct from every existing test in this codebase, which mocks the LLM and only checks that a
response *parses*, never whether it's *right*. Re-runs investigate_incident() against a random
sample of already-closed incidents (which still carry their saved threat_intel/asset/risk/
unique_values/org_context from when they were first investigated) and compares the fresh verdict
to the incident's recorded disposition.

Runs as a detached background task (see main.py's /api/eval/run), same asyncio.create_task
pattern as main.py's _run_large_alert_import — a sample of real AI calls takes real time and
burns real Bedrock budget, so it must never block the request that starts it.

Critical correctness requirement: a closed incident's own confirmed disposition is embedded into
ChromaDB at close time (rag.py's embed_case_resolution) and would otherwise be the single closest
precedent match when re-investigating that same incident — handed back to it as "evidence" about
itself. exclude_precedent_source (rag.py's investigate_incident()/_retrieve_context()) strips
exactly that one document out of retrieval for every eval call below.
"""
import logging
from datetime import datetime, timezone

from app.db import db, incidents
from app.rag import investigate_incident
from app.risk_score import compute_risk_score

logger = logging.getLogger("soc.eval_harness")

eval_reports = db["eval_reports"]
_REPORT_ID = "latest"

DISPOSITIONS = ("true_positive", "false_positive", "benign_positive")
# "needs_review" is a valid AI verdict but never a valid disposition (schemas.CloseIncidentRequest
# excludes it) — a fresh verdict landing there is scored as disagreement, not matched to any row.
_MATRIX_COLUMNS = DISPOSITIONS + ("needs_review", "unparsed")


async def get_latest_report() -> dict | None:
    return await eval_reports.find_one({"_id": _REPORT_ID})


async def run_eval(sample_size: int) -> None:
    """The actual sampling + scoring loop. Call via asyncio.create_task from a request handler,
    not directly — this makes real, billed AI calls and can run for a while."""
    started_at = datetime.now(timezone.utc).isoformat()
    await eval_reports.update_one(
        {"_id": _REPORT_ID},
        {"$set": {"status": "running", "sample_size_requested": sample_size, "started_at": started_at}},
        upsert=True,
    )

    try:
        pipeline = [
            {"$match": {"case_status": "closed", "disposition": {"$in": list(DISPOSITIONS)}}},
            {"$sample": {"size": sample_size}},
        ]
        sample = [doc async for doc in incidents.aggregate(pipeline)]

        matrix = {d: {c: 0 for c in _MATRIX_COLUMNS} for d in DISPOSITIONS}
        agreements = 0
        errors = 0

        for case in sample:
            disposition = case["disposition"]
            try:
                report = await investigate_incident(
                    case,
                    threat_intel=case.get("threat_intel"),
                    asset=case.get("asset"),
                    risk=compute_risk_score(case),
                    unique_values=case.get("unique_values"),
                    org_context=case.get("org_context"),
                    exclude_precedent_source=f"case-{case['_id']}",
                )
            except Exception:
                logger.exception("Eval run: investigation failed for incident %s; counted as an error", case["_id"])
                errors += 1
                continue

            verdict = report.get("verdict") or "unparsed"
            if verdict not in _MATRIX_COLUMNS:
                verdict = "unparsed"
            matrix[disposition][verdict] += 1
            if verdict == disposition:
                agreements += 1

        scored = len(sample) - errors
        await eval_reports.update_one(
            {"_id": _REPORT_ID},
            {"$set": {
                "status": "done",
                "sample_size_requested": sample_size,
                "sample_size_scored": scored,
                "errors": errors,
                "agreement_rate": round(agreements / scored, 4) if scored else None,
                "confusion_matrix": matrix,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            }},
        )
    except Exception as exc:
        logger.exception("Eval run failed")
        await eval_reports.update_one(
            {"_id": _REPORT_ID},
            {"$set": {"status": "error", "error": str(exc), "finished_at": datetime.now(timezone.utc).isoformat()}},
        )
