"""Lightweight in-process tracing for the Architecture Review Agent pipeline.

Provides a context-manager-based tracing system that records duration, status,
and attributes for each pipeline stage. Spans are stored in-memory on a
per-review basis and can later be connected to an external tracing backend
(e.g., OpenTelemetry).

Pipeline stages: parse, load_context, static_analysis, semantic_analysis,
                 generate_fixes, compose_response, persist
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import local
from typing import Any, Generator


# Valid pipeline stage names
PIPELINE_STAGES = (
    "parse",
    "load_context",
    "static_analysis",
    "semantic_analysis",
    "generate_fixes",
    "compose_response",
    "persist",
)


@dataclass
class TraceSpan:
    """A single trace span representing one pipeline stage execution."""

    stage_name: str
    duration_ms: float = 0.0
    status: str = "success"  # "success" | "error"
    attributes: dict[str, Any] = field(default_factory=dict)
    error_description: str | None = None


@dataclass
class ReviewTrace:
    """Holds the root span and all stage spans for a single review.

    The root span aggregates overall review metrics (total resources,
    total findings, review status). Stage spans record per-stage details.
    """

    root_attributes: dict[str, Any] = field(default_factory=dict)
    spans: list[TraceSpan] = field(default_factory=list)
    review_status: str = "success"  # "success" | "error"

    def add_span(self, span: TraceSpan) -> None:
        """Add a completed stage span to this trace."""
        self.spans.append(span)

    def set_root_attribute(self, key: str, value: Any) -> None:
        """Set an attribute on the root span."""
        self.root_attributes[key] = value

    def set_review_status(self, status: str) -> None:
        """Set the overall review status."""
        self.review_status = status

    def get_span(self, stage_name: str) -> TraceSpan | None:
        """Get a span by stage name, or None if not found."""
        for span in self.spans:
            if span.stage_name == stage_name:
                return span
        return None


# Thread-local storage for the current active trace
_trace_context = local()


def start_review_trace() -> ReviewTrace:
    """Create and activate a new ReviewTrace for the current review.

    Returns:
        The newly created ReviewTrace, which is also set as the current trace.
    """
    trace = ReviewTrace()
    _trace_context.current_trace = trace
    return trace


def get_current_trace() -> ReviewTrace | None:
    """Return the active ReviewTrace, or None if no review is in progress."""
    return getattr(_trace_context, "current_trace", None)


def clear_current_trace() -> None:
    """Clear the current trace context. Called after a review completes."""
    _trace_context.current_trace = None


def trace_to_dict(trace: ReviewTrace) -> dict[str, Any]:
    """Serialize a ReviewTrace to a plain dict for structured logging.

    Emitted to CloudWatch Logs so each review's per-stage timing and status are
    queryable in Logs Insights (a supplement to AgentCore's native OpenTelemetry
    traces). Shape:

        {"event": "review_trace", "review_status": "...",
         "total_duration_ms": <sum of stage durations>,
         "stages": [{"stage": "...", "duration_ms": ..., "status": "...",
                     "attributes": {...}, "error": "..."}],
         "root_attributes": {...}}
    """
    stages = [
        {
            "stage": span.stage_name,
            "duration_ms": round(span.duration_ms, 2),
            "status": span.status,
            "attributes": span.attributes,
            **({"error": span.error_description} if span.error_description else {}),
        }
        for span in trace.spans
    ]
    return {
        "event": "review_trace",
        "review_status": trace.review_status,
        "total_duration_ms": round(sum(s.duration_ms for s in trace.spans), 2),
        "stages": stages,
        "root_attributes": trace.root_attributes,
    }


@contextmanager
def trace_stage(
    stage_name: str, attributes: dict[str, Any] | None = None
) -> Generator[TraceSpan, None, None]:
    """Context manager that creates a trace span for a pipeline stage.

    Records:
    - Duration in milliseconds
    - Status: "success" or "error"
    - Additional attributes (token counts, resource counts, etc.)
    - Error description when a stage fails

    The span is automatically added to the current ReviewTrace (if one exists).

    Args:
        stage_name: Name of the pipeline stage (should be one of PIPELINE_STAGES).
        attributes: Optional dict of additional attributes to record on the span.

    Yields:
        The TraceSpan being recorded. Callers can add extra attributes to it
        during execution.

    Example:
        with trace_stage("static_analysis", {"resource_count": 10}) as span:
            findings = run_analysis(graph)
            span.attributes["findings_count"] = len(findings)
    """
    span = TraceSpan(
        stage_name=stage_name,
        attributes=dict(attributes) if attributes else {},
    )

    start_time = time.perf_counter()
    try:
        yield span
        span.status = "success"
    except Exception as exc:
        span.status = "error"
        span.error_description = str(exc)
        raise
    finally:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        span.duration_ms = elapsed_ms

        # Attach to current trace if one exists
        trace = get_current_trace()
        if trace is not None:
            trace.add_span(span)
