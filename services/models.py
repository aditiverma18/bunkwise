from dataclasses import dataclass, field
from datetime import date, time
from enum import Enum
from typing import List, Optional,Any


@dataclass
class LectureContext:
    # ---------- Lecture Information ----------
    subject: str
    lecture_date: date
    start_time: time
    end_time: time
    lecture_type: str = "Theory"      # Theory / Lab / Tutorial

    # ---------- Attendance Information ----------
    classes_attended: int
    classes_conducted: int
    minimum_required: float = 75.0
    remaining_bunks: int = 0

    # ---------- Academic Context ----------
    upcoming_events: List[str] = field(default_factory=list)

    # Example:
    # ["Present", "Absent", "Present", "Present"]
    attendance_pattern: List[str] = field(default_factory=list)

    # ---------- Metadata ----------
    is_holiday: bool = False
    is_cancelled: bool = False
    attendance_marked: bool = False


from dataclasses import dataclass

@dataclass
class AnalyzerResult:
    analyzer_name: str
    score: int
    severity: str
    reason: str

    data: dict[str, Any] = field(default_factory=dict)


from dataclasses import dataclass, field
from typing import List


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

