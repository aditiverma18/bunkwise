from dataclasses import dataclass, field
from datetime import date, time
from typing import List,Any

@dataclass
class AcademicEvent:
    title: str
    subject:str
    event_type: str
    event_date: date
    priority: str

@dataclass
class LectureContext:

    # ---------- Required ----------

    subject: str

    classes_attended: int
    classes_conducted: int

    # ---------- Optional ----------

    lecture_date: date | None = None
    start_time: time | None = None
    end_time: time | None = None

    lecture_type: str = "Theory"

    minimum_required: float = 75.0
    remaining_bunks: int = 0

    upcoming_events: List[AcademicEvent] = field(default_factory=list)

    attendance_pattern: List[str] = field(default_factory=list)

    is_holiday: bool = False
    is_cancelled: bool = False
    attendance_marked: bool = False

from dataclasses import dataclass, field
from typing import List , Any


@dataclass
class AnalyzerResult:
    analyzer_name: str
    score: int                  # 0–100 normalized score
    severity: str               # LOW / MEDIUM / HIGH / CRITICAL
    reason: str                 # Human-readable explanation

    data: dict[str, Any] = field(default_factory=dict)



@dataclass
class Decision:
    recommendation: str          # Attend / Optional / Safe to Skip
    confidence: float            # 0-100
    risk: str                    # LOW / MEDIUM / HIGH

    current_attendance: float
    projected_if_attend: float
    projected_if_skip: float

    remaining_bunks: int

    reasons: List[str] = field(default_factory=list)

    analyzer_results: List[AnalyzerResult] = field(default_factory=list)

