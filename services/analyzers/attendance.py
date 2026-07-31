from services.models import LectureContext, AnalyzerResult


class AttendanceAnalyzer:

    def calculate_current(self, context: LectureContext) -> float:
        """Returns the current attendance percentage."""

        attended = context.classes_attended
        conducted = context.classes_conducted

        if conducted == 0:
            return 100.0

        return round((attended / conducted) * 100, 2)

    def calculate_after_attend(self, context: LectureContext) -> float:
        """Returns attendance percentage if the next lecture is attended."""

        attended = context.classes_attended
        conducted = context.classes_conducted

        return round(((attended + 1) / (conducted + 1)) * 100, 2)

    def calculate_after_skip(self, context: LectureContext) -> float:
        """Returns attendance percentage if the next lecture is skipped."""

        attended = context.classes_attended
        conducted = context.classes_conducted

        return round((attended / (conducted + 1)) * 100, 2)

    def classify_health(self, attendance: float):
         if attendance >= 90:
           return ("Excellent", 100, "LOW")

         elif attendance >= 85:
           return ("Healthy", 80, "LOW")

         elif attendance >= 80:
          return ("Watch", 60, "MEDIUM")

         elif attendance >= 75:
          return ("Critical", 40, "HIGH")

         else:
          return ("Unsafe", 10, "CRITICAL")

    def analyze(self, context: LectureContext) -> AnalyzerResult:
       current = self.calculate_current(context)
       after_attend = self.calculate_after_attend(context)
       after_skip = self.calculate_after_skip(context)

       margin = round(current - context.minimum_required, 2)

       health, score, severity = self.classify_health(current)

       return AnalyzerResult(
        analyzer_name="Attendance Analyzer",
        score=score,
        severity=severity,
       reason = (
         f"Current attendance is {current}%, "
         f"which is classified as {health.lower()}."
         ),
        data={
            "current": current,
            "after_attend": after_attend,
            "after_skip": after_skip,
            "margin": margin,
            "health": health
        }
    )