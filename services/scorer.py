from services.models import AnalyzerResult, Decision


class DecisionScorer:

    def calculate_final_score(self, analyzer_results):
         weighted_score = 0
         total_weight = 0

         for result in analyzer_results:
          weight = self.WEIGHTS.get(result.analyzer_name, 0)
          weighted_score += result.score * weight
          total_weight += weight

         if total_weight == 0:
           return 0

         return round(weighted_score / total_weight, 2)

    
    def generate_decision(self, analyzer_results):

       final_score = self.calculate_final_score(analyzer_results)

       if final_score >= 85:
         recommendation = "Safe to Skip"
         risk = "LOW"

       elif final_score >= 70:
        recommendation = "Probably Safe"
        risk = "LOW"

       elif final_score >= 50:
        recommendation = "Optional"
        risk = "MEDIUM"

       elif final_score >= 30:
        recommendation = "Better Attend"
        risk = "HIGH"

       else:
        recommendation = "Attend"
        risk = "CRITICAL"

       attendance_data = {}
       budget_data = {}

       for result in analyzer_results:

        if result.analyzer_name == "Attendance Analyzer":
            attendance_data = result.data

        elif result.analyzer_name == "Budget Analyzer":
            budget_data = result.data

       return Decision(
        recommendation=recommendation,
        confidence=final_score,
        risk=risk,

        current_attendance=attendance_data.get("current", 0),
        projected_if_attend=attendance_data.get("after_attend", 0),
        projected_if_skip=attendance_data.get("after_skip", 0),

        remaining_bunks=budget_data.get("remaining_bunks", 0),

        reasons=[result.reason for result in analyzer_results],
        analyzer_results=analyzer_results
    )