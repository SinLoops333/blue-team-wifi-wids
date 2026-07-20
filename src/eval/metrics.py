"""Classification metrics helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Sequence, Set


@dataclass
class BinaryScores:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def support_positive(self) -> int:
        return self.tp + self.fn

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "support_positive": self.support_positive,
        }


def scores_for_label(
    y_true: Sequence[int], y_pred: Sequence[int]
) -> BinaryScores:
    """Binary labels: 1 = positive class."""
    s = BinaryScores()
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            s.tp += 1
        elif t == 0 and p == 1:
            s.fp += 1
        elif t == 0 and p == 0:
            s.tn += 1
        elif t == 1 and p == 0:
            s.fn += 1
    return s


def multilabel_alert_scores(
    expected_per_scenario: List[Set[str]],
    predicted_per_scenario: List[Set[str]],
    alert_types: Iterable[str],
) -> Dict[str, BinaryScores]:
    """Per alert-type presence detection across scenarios."""
    types = list(alert_types)
    out: Dict[str, BinaryScores] = {t: BinaryScores() for t in types}
    for exp, pred in zip(expected_per_scenario, predicted_per_scenario):
        for t in types:
            truth = 1 if t in exp else 0
            guess = 1 if t in pred else 0
            s = out[t]
            if truth == 1 and guess == 1:
                s.tp += 1
            elif truth == 0 and guess == 1:
                s.fp += 1
            elif truth == 0 and guess == 0:
                s.tn += 1
            else:
                s.fn += 1
    return out
