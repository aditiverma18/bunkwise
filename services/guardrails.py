from typing import Optional

from services.models import Decision, LectureContext


def _create_guardrail_decision(
    recommendation: str,
    risk: str,
    reason: str,
    context: LectureContext,
) -> Decision:
    return Decision(
        recommendation=recommendation,
        confidence=100.0,
        risk=risk,
        current_attendance=context.attendance_percentage,
        projected_if_attend=context.attendance_percentage,
        projected_if_skip=context.attendance_percentage,
        remaining_bunks=context.remaining_bunks,
        reasons=[reason],
        analyzer_results=[],
    )


def check_guardrails(context: LectureContext) -> Optional[Decision]:

    if context.is_holiday:
        return _create_guardrail_decision(
            recommendation="NO_ACTION",
            risk="NONE",
            reason="Today is a holiday.",
            context=context,
        )

    if context.is_cancelled:
        return _create_guardrail_decision(
            recommendation="NO_ACTION",
            risk="NONE",
            reason="Lecture has been cancelled.",
            context=context,
        )

    if context.attendance_marked:
        return _create_guardrail_decision(
            recommendation="NO_ACTION",
            risk="NONE",
            reason="Attendance has already been marked.",
            context=context,
        )

    if context.attendance_percentage < context.minimum_required:
        return _create_guardrail_decision(
            recommendation="ATTEND",
            risk="HIGH",
            reason="Attendance is below the minimum required percentage.",
            context=context,
        )

    return None