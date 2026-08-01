from services.models import AnalyzerResult, LectureContext


class PatternAnalyzer:

    def calculate_attendance_rate(self, pattern):

        if not pattern:
            return 100

        present = pattern.count("P")

        return round((present / len(pattern)) * 100, 2)

    def consecutive_absences(self, pattern):

        count = 0

        for status in reversed(pattern):

            if status == "A":
                count += 1
            else:
                break

        return count

    def consecutive_presents(self, pattern):

        count = 0

        for status in reversed(pattern):

            if status == "P":
                count += 1
            else:
                break

        return count

    def classify_pattern(self, attendance_rate,
                         absences,
                         presents):

        if absences >= 3:
            return ("Poor", 20, "HIGH")

        if attendance_rate >= 90:
            return ("Excellent", 100, "LOW")

        if attendance_rate >= 80:
            return ("Healthy", 80, "LOW")

        if attendance_rate >= 70:
            return ("Watch", 60, "MEDIUM")

        return ("Risky", 30, "HIGH")

    def analyze(self, context: LectureContext):

        pattern = context.attendance_pattern

        rate = self.calculate_attendance_rate(pattern)

        absences = self.consecutive_absences(pattern)

        presents = self.consecutive_presents(pattern)

        health, score, severity = self.classify_pattern(
            rate,
            absences,
            presents
        )

        return AnalyzerResult(
            analyzer_name="Pattern Analyzer",
            score=score,
            severity=severity,
            reason=(
                f"Recent attendance pattern is "
                f"{health.lower()}."
            ),
            data={
                "attendance_rate": rate,
                "consecutive_absences": absences,
                "consecutive_presents": presents,
                "health": health
            }
        )