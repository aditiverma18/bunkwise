from services.analyzers.attendance import AttendanceAnalyzer
from services.analyzers.budget import BudgetAnalyzer
from services.guardrails import check_guardrails
from services.models import LectureContext
from services.scorer import DecisionScorer
from services.analyzers.events import EventAnalyzer
from services.analyzers.patterns import PatternAnalyzer

class RecommendationEngine:

    def __init__(self):

        self.attendance_analyzer = AttendanceAnalyzer()
        self.budget_analyzer = BudgetAnalyzer()
        self.scorer = DecisionScorer()
        self.event_analyzer = EventAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()


    def evaluate(self, context: LectureContext):

        # Check guard rails first
        decision = check_guardrails(context)

        if decision:
            return decision

        analyzer_results = []

        analyzer_results.append(
           self.attendance_analyzer.analyze(context)
)

        analyzer_results.append(
            self.budget_analyzer.analyze(context)
)

        analyzer_results.append(
             self.event_analyzer.analyze(context)
)

        analyzer_results.append(
    self.pattern_analyzer.analyze(context)
)

        return self.scorer.generate_decision(analyzer_results)