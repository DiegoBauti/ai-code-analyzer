from typing import List, Dict
from .models import Finding, ScanResult


def precision(tp: int, fp: int) -> float:

    if tp + fp == 0:
        return 0.0
    return tp / (tp + fp)


def recall(tp: int, fn: int) -> float:

    if tp + fn == 0:
        return 0.0
    return tp / (tp + fn)


def f1_score(tp: int, fp: int, fn: int) -> float:

    p = precision(tp, fp)
    r = recall(tp, fn)
    if p + r == 0:
        return 0.0
    return 2 * (p * r) / (p + r)


def accuracy(tp: int, tn: int, fp: int, fn: int) -> float:

    total = tp + tn + fp + fn
    if total == 0:
        return 0.0
    return (tp + tn) / total


def calculate_confusion(scan_results: List[ScanResult]) -> Dict[str, int]:

    tp = fp = fn = 0

    for result in scan_results:
        for f in result.findings:
            if f.is_true_positive is True:
                tp += 1
            elif f.is_true_positive is False:
                fp += 1
            else:
                fn += 1

    return {"tp": tp, "fp": fp, "fn": fn}


def calculate_metrics(scan_results: List[ScanResult], tn: int = 0) -> Dict[str, float]:

    confusion = calculate_confusion(scan_results)
    tp = confusion["tp"]
    fp = confusion["fp"]
    fn = confusion["fn"]

    return {
        "precision": precision(tp, fp),
        "recall": recall(tp, fn),
        "f1_score": f1_score(tp, fp, fn),
        "accuracy": accuracy(tp, tn, fp, fn),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn
    }


if __name__ == "__main__":
    from .models import Finding, FindingSource, Severity


    class DummyScanResult:
        def __init__(self, findings):
            self.findings = findings


    finding1 = Finding(
        file_path="test.py",
        start_line=1,
        end_line=1,
        vulnerability_type="Test",
        description="Test",
        recommendation="Test",
        confidence=0.9,
        source=FindingSource.STATIC,
        is_true_positive=True
    )

    finding2 = Finding(
        file_path="test.py",
        start_line=2,
        end_line=2,
        vulnerability_type="Test",
        description="Test",
        recommendation="Test",
        confidence=0.8,
        source=FindingSource.STATIC,
        is_true_positive=False
    )

    finding3 = Finding(
        file_path="test.py",
        start_line=3,
        end_line=3,
        vulnerability_type="Test",
        description="Test",
        recommendation="Test",
        confidence=0.7,
        source=FindingSource.STATIC
    )

    results = [
        DummyScanResult([finding1, finding2, finding3])
    ]

    metrics = calculate_metrics(results, tn=10)
    print("Métricas de prueba:")
    for k, v in metrics.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")
        else:
            print(f"  {k}: {v}")