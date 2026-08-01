from services.models import AcademicEvent, AnalyzerResult, LectureContext


class EventAnalyzer:

    def classify_event(self, event: AcademicEvent, days_remaining: int):

        # Event is today or tomorrow
        if days_remaining <= 1:

            if event.event_type == "Midsem":
                return ("Critical", 10, "CRITICAL")

            elif event.event_type == "Quiz":
                return ("Important", 20, "HIGH")

            elif event.event_type == "Lab":
                return ("Important", 30, "HIGH")

            elif event.event_type == "Assignment":
                return ("Moderate", 40, "MEDIUM")

            elif event.event_type == "Holiday":
                return ("Relaxed", 100, "LOW")

        # Event within this week
        elif days_remaining <= 7:

            if event.event_type == "Midsem":
                return ("Critical", 20, "HIGH")

            elif event.event_type == "Quiz":
                return ("Important", 40, "MEDIUM")

            elif event.event_type == "Lab":
                return ("Important", 50, "MEDIUM")

            elif event.event_type == "Assignment":
                return ("Moderate", 60, "LOW")

            elif event.event_type == "Holiday":
                return ("Relaxed", 100, "LOW")

        # Event is far away
        else:

            if event.event_type == "Midsem":
                return ("Critical", 50, "MEDIUM")

            elif event.event_type == "Quiz":
                return ("Important", 65, "LOW")

            elif event.event_type == "Lab":
                return ("Important", 70, "LOW")

            elif event.event_type == "Assignment":
                return ("Moderate", 75, "LOW")

            elif event.event_type == "Holiday":
                return ("Relaxed", 100, "LOW")

        return ("Neutral", 80, "LOW")

    def analyze(self, context: LectureContext) -> AnalyzerResult:

        # Keep only events related to this subject
        subject_events = [
            event
            for event in context.upcoming_events
            if event.subject == context.subject
        ]

        if not subject_events:
            return AnalyzerResult(
                analyzer_name="Events Analyzer",
                score=80,
                severity="LOW",
                reason="No upcoming events for this subject.",
                data={}
            )

        # Find the nearest event
        nearest_event = min(
            subject_events,
            key=lambda event: (event.event_date - context.lecture_date).days
        )

        days_remaining = (
            nearest_event.event_date - context.lecture_date
        ).days

        status, score, severity = self.classify_event(
            nearest_event,
            days_remaining
        )

        return AnalyzerResult(
            analyzer_name="Events Analyzer",
            score=score,
            severity=severity,
            reason=(
                f"{nearest_event.event_type} "
                f"'{nearest_event.title}' "
                f"in {days_remaining} day(s)."
            ),
            data={
                "event": nearest_event.title,
                "subject": nearest_event.subject,
                "event_type": nearest_event.event_type,
                "priority": nearest_event.priority,
                "days_remaining": days_remaining,
                "status": status
            }
        )