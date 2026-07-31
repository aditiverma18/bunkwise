from services.models import LectureContext, AnalyzerResult


class BudgetAnalyzer:

    def classify_budget(self, remaining_bunks: int):

        if remaining_bunks >= 5:
            return ("Excellent", 100, "LOW")

        elif remaining_bunks >= 3:
            return ("Healthy", 80, "LOW")

        elif remaining_bunks >= 1:
            return ("Watch", 60, "MEDIUM")

        else:
            return ("Critical", 20, "HIGH")

    def analyze(self, context: LectureContext) -> AnalyzerResult:

        budget, score, severity = self.classify_budget(
            context.remaining_bunks
        )

        return AnalyzerResult(
            analyzer_name="Budget Analyzer",
            score=score,
            severity=severity,
            reason=(
                f"{context.remaining_bunks} safe bunk(s) remaining "
                f"({budget.lower()})."
            ),
            data={
                "remaining_bunks": context.remaining_bunks,
                "budget": budget
            }
        )