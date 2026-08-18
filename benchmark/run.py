"""Run every arm against every scenario and attribute the difference.

The headline number is not "did the arm succeed" but **what the world ended up
with**: how many times money actually moved.  That is read from the payment
world, not from what any arm believed.

Attribution follows the ablation design: each single-mechanism arm is compared
with A, so a gain belongs to that mechanism.  Anything that only appears in E is
reported as a combination effect rather than credited to a part.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmark.arms.variants import ARMS  # noqa: E402
from benchmark.harness.world import PaymentWorld, Scenario  # noqa: E402
from benchmark.scenarios.catalog import SCENARIOS  # noqa: E402

INTENT = {"intent_id": "intent-1", "amount": 1000}


@dataclass
class Measurement:
    """One arm in one scenario, measured against ground truth."""

    arm: str
    scenario: str
    charges_performed: int          # ground truth: times money actually moved
    duplicate_side_effects: int     # charges beyond the first
    unauthorized_side_effects: int  # charges outside the approved scope
    false_retries: int              # retries after an effect had already happened
    unresolved: int                 # ended without knowing what happened
    missed_completions: int         # correct work left undone (cost of caution)
    final_state: str
    evidence_records: int


def measure(arm_class: type, scenario: Scenario) -> Measurement:
    world = PaymentWorld(
        supports_idempotency=scenario.supports_idempotency,
        supports_lookup=scenario.supports_lookup,
    )
    arm = arm_class(world)
    result = arm.run(scenario, dict(INTENT))

    charges = world.charge_count(INTENT["intent_id"])
    unauthorized = sum(
        1 for charge in world.charges if charge.amount != INTENT["amount"]
    )
    # A retry counts as false when the effect had already happened at that point.
    false_retries = max(0, charges - 1) if result.retries_after_uncertainty else 0
    unresolved = 1 if result.final_state in {"PERMANENTLY_UNRESOLVED", "EXHAUSTED"} else 0
    # Refusing to ever retry buys zero duplicates by leaving legitimate work
    # undone. Without this metric an arm that simply gives up looks perfect.
    missed = 1 if scenario.should_complete and charges == 0 else 0

    return Measurement(
        arm=arm.name,
        scenario=scenario.name,
        charges_performed=charges,
        duplicate_side_effects=max(0, charges - 1),
        unauthorized_side_effects=unauthorized,
        false_retries=false_retries,
        unresolved=unresolved,
        missed_completions=missed,
        final_state=result.final_state,
        evidence_records=len(result.evidence),
    )


def run_all() -> list[Measurement]:
    return [measure(arm, scenario) for scenario in SCENARIOS for arm in ARMS]


def totals(measurements: list[Measurement]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for measurement in measurements:
        bucket = summary.setdefault(
            measurement.arm,
            {"duplicate_side_effects": 0, "unauthorized_side_effects": 0,
             "false_retries": 0, "unresolved": 0, "missed_completions": 0,
             "evidence_records": 0},
        )
        bucket["duplicate_side_effects"] += measurement.duplicate_side_effects
        bucket["unauthorized_side_effects"] += measurement.unauthorized_side_effects
        bucket["false_retries"] += measurement.false_retries
        bucket["unresolved"] += measurement.unresolved
        bucket["missed_completions"] += measurement.missed_completions
        bucket["evidence_records"] += measurement.evidence_records
    return summary


def attribute(summary: dict[str, dict[str, int]]) -> dict[str, Any]:
    """Credit each mechanism with what it changed relative to arm A."""
    baseline = summary["A"]
    attribution: dict[str, Any] = {}
    for arm, label in (("B", "exact scope binding"), ("C", "single-use lease"),
                       ("D", "UNKNOWN + reconciliation")):
        attribution[arm] = {
            "mechanism": label,
            "duplicate_side_effects_prevented":
                baseline["duplicate_side_effects"] - summary[arm]["duplicate_side_effects"],
            "unauthorized_side_effects_prevented":
                baseline["unauthorized_side_effects"] - summary[arm]["unauthorized_side_effects"],
            "false_retries_prevented":
                baseline["false_retries"] - summary[arm]["false_retries"],
            "completions_lost":
                summary[arm]["missed_completions"] - baseline["missed_completions"],
        }

    single_best = {
        metric: max(attribution[arm][metric] for arm in ("B", "C", "D"))
        for metric in ("duplicate_side_effects_prevented",
                       "unauthorized_side_effects_prevented",
                       "false_retries_prevented")
    }
    full = {
        "duplicate_side_effects_prevented":
            baseline["duplicate_side_effects"] - summary["E"]["duplicate_side_effects"],
        "unauthorized_side_effects_prevented":
            baseline["unauthorized_side_effects"] - summary["E"]["unauthorized_side_effects"],
        "false_retries_prevented":
            baseline["false_retries"] - summary["E"]["false_retries"],
    }
    attribution["E"] = {
        "mechanism": "full combination",
        **full,
        "combination_effect": {
            metric: full[metric] - single_best[metric] for metric in full
        },
    }
    return attribution


def render(measurements: list[Measurement], summary: dict[str, dict[str, int]],
           attribution: dict[str, Any]) -> str:
    lines = ["# AP2 fault-injection ablation", "",
             "Ground truth is the payment world: charges performed, not charges believed.",
             "", "## Per-scenario charges performed", ""]
    arms = [arm.name for arm in ARMS]
    lines.append("| scenario | " + " | ".join(arms) + " |")
    lines.append("|---" * (len(arms) + 1) + "|")
    for scenario in SCENARIOS:
        row = [scenario.name]
        for arm in arms:
            found = next(m for m in measurements
                         if m.arm == arm and m.scenario == scenario.name)
            marker = "" if found.duplicate_side_effects == 0 else " ⚠"
            row.append(f"{found.charges_performed}{marker}")
        lines.append("| " + " | ".join(row) + " |")

    lines += ["", "## Totals across all scenarios", "",
              "| arm | duplicate | unauthorized | false retries | unresolved | work left undone |",
              "|---|---|---|---|---|---|"]
    for arm in arms:
        bucket = summary[arm]
        lines.append(
            f"| {arm} | {bucket['duplicate_side_effects']} | "
            f"{bucket['unauthorized_side_effects']} | {bucket['false_retries']} | "
            f"{bucket['unresolved']} | {bucket['missed_completions']} |"
        )

    lines += ["", "## Attribution (relative to arm A)", ""]
    for arm in ("B", "C", "D", "E"):
        entry = attribution[arm]
        lines.append(f"**{arm} — {entry['mechanism']}**")
        lines.append(f"- duplicate side effects prevented: {entry['duplicate_side_effects_prevented']}")
        lines.append(f"- unauthorized side effects prevented: {entry['unauthorized_side_effects_prevented']}")
        lines.append(f"- false retries prevented: {entry['false_retries_prevented']}")
        if entry.get("completions_lost"):
            lines.append(f"- **cost**: {entry['completions_lost']} legitimate completion(s) lost")
        if arm == "E":
            extra = entry["combination_effect"]
            unattributable = {k: v for k, v in extra.items() if v > 0}
            if unattributable:
                lines.append(f"- beyond the best single mechanism (UNATTRIBUTABLE to one part): {unattributable}")
            else:
                lines.append("- no gain beyond the best single mechanism on these metrics")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the AP2 fault-injection ablation.")
    parser.add_argument("--json", action="store_true", help="emit raw measurements")
    parser.add_argument("--out", type=Path, help="write the report to a file")
    arguments = parser.parse_args(argv)

    measurements = run_all()
    summary = totals(measurements)
    attribution = attribute(summary)

    if arguments.json:
        print(json.dumps(
            {"measurements": [asdict(m) for m in measurements],
             "totals": summary, "attribution": attribution},
            ensure_ascii=False, indent=2,
        ))
        return 0

    report = render(measurements, summary, attribution)
    if arguments.out:
        arguments.out.write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
