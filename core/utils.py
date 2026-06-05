from core.models import Finding

def create_finding(
    title: str,
    severity: str,
    confidence: float,
    source: str,
    type_: str,
    target: str
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        source=source,
        type=type_,
        target=target
    )
