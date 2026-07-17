"""Unit tests for the tracing module.

Tests cover:
- TraceSpan creation and attributes
- ReviewTrace lifecycle (create, add spans, set attributes)
- trace_stage context manager (success, error, timing, attributes)
- start_review_trace / get_current_trace / clear_current_trace
- All 7 pipeline stages traced correctly
- Root span attribute recording (total resources, findings, status)
"""

import time

import pytest

from src.tracing import (
    PIPELINE_STAGES,
    ReviewTrace,
    TraceSpan,
    clear_current_trace,
    get_current_trace,
    start_review_trace,
    trace_stage,
    trace_to_dict,
)


# ---------------------------------------------------------------------------
# trace_to_dict tests (structured logging for CloudWatch observability)
# ---------------------------------------------------------------------------


class TestTraceToDict:
    """Tests for serializing a ReviewTrace to a structured-log dict."""

    def test_serializes_stages_and_status(self):
        trace = ReviewTrace()
        trace.add_span(TraceSpan(stage_name="parse", duration_ms=1.5,
                                 status="success", attributes={"resource_count": 2}))
        trace.add_span(TraceSpan(stage_name="semantic_analysis", duration_ms=900.0,
                                 status="success", attributes={"findings_count": 5}))
        trace.set_review_status("success")

        d = trace_to_dict(trace)
        assert d["event"] == "review_trace"
        assert d["review_status"] == "success"
        assert d["total_duration_ms"] == 901.5
        assert [s["stage"] for s in d["stages"]] == ["parse", "semantic_analysis"]
        assert d["stages"][0]["attributes"]["resource_count"] == 2

    def test_includes_error_when_present(self):
        trace = ReviewTrace()
        span = TraceSpan(stage_name="parse", duration_ms=0.2, status="error")
        span.error_description = "boom"
        trace.add_span(span)
        trace.set_review_status("error")

        d = trace_to_dict(trace)
        assert d["review_status"] == "error"
        assert d["stages"][0]["error"] == "boom"

    def test_empty_trace_serializes(self):
        d = trace_to_dict(ReviewTrace())
        assert d["stages"] == []
        assert d["total_duration_ms"] == 0


# ---------------------------------------------------------------------------
# TraceSpan tests
# ---------------------------------------------------------------------------


class TestTraceSpan:
    """Tests for the TraceSpan dataclass."""

    def test_default_values(self):
        span = TraceSpan(stage_name="parse")
        assert span.stage_name == "parse"
        assert span.duration_ms == 0.0
        assert span.status == "success"
        assert span.attributes == {}
        assert span.error_description is None

    def test_custom_attributes(self):
        span = TraceSpan(
            stage_name="semantic_analysis",
            attributes={"input_tokens": 500, "output_tokens": 200},
        )
        assert span.attributes["input_tokens"] == 500
        assert span.attributes["output_tokens"] == 200

    def test_error_state(self):
        span = TraceSpan(
            stage_name="parse",
            status="error",
            error_description="Invalid YAML at line 5",
        )
        assert span.status == "error"
        assert span.error_description == "Invalid YAML at line 5"


# ---------------------------------------------------------------------------
# ReviewTrace tests
# ---------------------------------------------------------------------------


class TestReviewTrace:
    """Tests for the ReviewTrace class."""

    def test_initial_state(self):
        trace = ReviewTrace()
        assert trace.spans == []
        assert trace.root_attributes == {}
        assert trace.review_status == "success"

    def test_add_span(self):
        trace = ReviewTrace()
        span = TraceSpan(stage_name="parse", duration_ms=12.5, status="success")
        trace.add_span(span)
        assert len(trace.spans) == 1
        assert trace.spans[0] is span

    def test_add_multiple_spans(self):
        trace = ReviewTrace()
        for stage in PIPELINE_STAGES:
            trace.add_span(TraceSpan(stage_name=stage))
        assert len(trace.spans) == 7

    def test_set_root_attribute(self):
        trace = ReviewTrace()
        trace.set_root_attribute("total_resources", 15)
        trace.set_root_attribute("total_findings", 3)
        assert trace.root_attributes["total_resources"] == 15
        assert trace.root_attributes["total_findings"] == 3

    def test_set_review_status(self):
        trace = ReviewTrace()
        assert trace.review_status == "success"
        trace.set_review_status("error")
        assert trace.review_status == "error"

    def test_get_span_found(self):
        trace = ReviewTrace()
        span = TraceSpan(stage_name="static_analysis", duration_ms=50.0)
        trace.add_span(span)
        found = trace.get_span("static_analysis")
        assert found is span

    def test_get_span_not_found(self):
        trace = ReviewTrace()
        assert trace.get_span("nonexistent") is None


# ---------------------------------------------------------------------------
# Context management tests
# ---------------------------------------------------------------------------


class TestTraceContext:
    """Tests for start_review_trace, get_current_trace, clear_current_trace."""

    def setup_method(self):
        """Ensure clean state before each test."""
        clear_current_trace()

    def teardown_method(self):
        """Clean up after each test."""
        clear_current_trace()

    def test_no_trace_by_default(self):
        assert get_current_trace() is None

    def test_start_review_trace_returns_trace(self):
        trace = start_review_trace()
        assert isinstance(trace, ReviewTrace)

    def test_start_review_trace_sets_current(self):
        trace = start_review_trace()
        assert get_current_trace() is trace

    def test_clear_current_trace(self):
        start_review_trace()
        clear_current_trace()
        assert get_current_trace() is None

    def test_start_new_trace_replaces_current(self):
        trace1 = start_review_trace()
        trace2 = start_review_trace()
        assert get_current_trace() is trace2
        assert trace1 is not trace2


# ---------------------------------------------------------------------------
# trace_stage context manager tests
# ---------------------------------------------------------------------------


class TestTraceStage:
    """Tests for the trace_stage context manager."""

    def setup_method(self):
        clear_current_trace()

    def teardown_method(self):
        clear_current_trace()

    def test_successful_stage_records_success(self):
        start_review_trace()
        with trace_stage("parse") as span:
            pass  # simulate work
        assert span.status == "success"
        assert span.duration_ms >= 0.0
        assert span.error_description is None

    def test_failing_stage_records_error(self):
        start_review_trace()
        with pytest.raises(ValueError, match="bad template"):
            with trace_stage("parse") as span:
                raise ValueError("bad template")

        assert span.status == "error"
        assert span.error_description == "bad template"
        assert span.duration_ms >= 0.0

    def test_duration_is_measured(self):
        start_review_trace()
        with trace_stage("static_analysis") as span:
            time.sleep(0.01)  # sleep 10ms
        # Should be at least ~10ms
        assert span.duration_ms >= 5.0

    def test_attributes_passed_at_creation(self):
        start_review_trace()
        with trace_stage("semantic_analysis", {"input_tokens": 100}) as span:
            pass
        assert span.attributes["input_tokens"] == 100

    def test_attributes_added_during_execution(self):
        start_review_trace()
        with trace_stage("static_analysis") as span:
            span.attributes["findings_count"] = 5
            span.attributes["resource_count"] = 10
        assert span.attributes["findings_count"] == 5
        assert span.attributes["resource_count"] == 10

    def test_span_added_to_current_trace_on_success(self):
        trace = start_review_trace()
        with trace_stage("parse"):
            pass
        assert len(trace.spans) == 1
        assert trace.spans[0].stage_name == "parse"
        assert trace.spans[0].status == "success"

    def test_span_added_to_current_trace_on_error(self):
        trace = start_review_trace()
        with pytest.raises(RuntimeError):
            with trace_stage("load_context"):
                raise RuntimeError("memory unavailable")
        assert len(trace.spans) == 1
        assert trace.spans[0].stage_name == "load_context"
        assert trace.spans[0].status == "error"
        assert trace.spans[0].error_description == "memory unavailable"

    def test_no_trace_context_still_works(self):
        """trace_stage works even when no ReviewTrace is active."""
        clear_current_trace()
        with trace_stage("parse") as span:
            pass
        assert span.status == "success"
        assert span.duration_ms >= 0.0

    def test_error_stage_still_records_prior_stages(self):
        """Requirement 12.4: trace spans emitted for stages before failure."""
        trace = start_review_trace()

        with trace_stage("parse"):
            pass

        with trace_stage("load_context"):
            pass

        with pytest.raises(ValueError):
            with trace_stage("static_analysis"):
                raise ValueError("rule evaluation failed")

        assert len(trace.spans) == 3
        assert trace.spans[0].stage_name == "parse"
        assert trace.spans[0].status == "success"
        assert trace.spans[1].stage_name == "load_context"
        assert trace.spans[1].status == "success"
        assert trace.spans[2].stage_name == "static_analysis"
        assert trace.spans[2].status == "error"


# ---------------------------------------------------------------------------
# Full pipeline trace tests
# ---------------------------------------------------------------------------


class TestFullPipelineTrace:
    """Tests simulating all 7 pipeline stages being traced."""

    def setup_method(self):
        clear_current_trace()

    def teardown_method(self):
        clear_current_trace()

    def test_all_seven_stages_traced(self):
        """Requirement 12.1: trace span for each of the 7 pipeline stages."""
        trace = start_review_trace()

        for stage in PIPELINE_STAGES:
            with trace_stage(stage):
                pass

        assert len(trace.spans) == 7
        recorded_stages = [s.stage_name for s in trace.spans]
        assert recorded_stages == list(PIPELINE_STAGES)
        for span in trace.spans:
            assert span.status == "success"
            assert span.duration_ms >= 0.0

    def test_semantic_analysis_token_counts(self):
        """Requirement 12.2: record token counts for semantic analysis."""
        trace = start_review_trace()

        with trace_stage(
            "semantic_analysis",
            {"input_tokens": 1500, "output_tokens": 800},
        ) as span:
            pass

        sa_span = trace.get_span("semantic_analysis")
        assert sa_span is not None
        assert sa_span.attributes["input_tokens"] == 1500
        assert sa_span.attributes["output_tokens"] == 800

    def test_root_span_records_totals(self):
        """Requirement 12.3: total resource count, findings count, status."""
        trace = start_review_trace()

        # Simulate running pipeline and recording root attributes
        trace.set_root_attribute("total_resources", 25)
        trace.set_root_attribute("total_findings", 7)
        trace.set_review_status("success")

        assert trace.root_attributes["total_resources"] == 25
        assert trace.root_attributes["total_findings"] == 7
        assert trace.review_status == "success"

    def test_pipeline_with_partial_failure(self):
        """Requirement 12.4: spans emitted for stages prior to failure."""
        trace = start_review_trace()

        # Stages 1-3 succeed
        with trace_stage("parse", {"resource_count": 10}):
            pass
        with trace_stage("load_context"):
            pass
        with trace_stage("static_analysis", {"findings_count": 3}):
            pass

        # Stage 4 fails
        with pytest.raises(TimeoutError):
            with trace_stage("semantic_analysis"):
                raise TimeoutError("FM invocation timed out")

        # Record root span failure
        trace.set_review_status("error")

        # Verify all 4 spans exist
        assert len(trace.spans) == 4
        assert trace.spans[0].status == "success"
        assert trace.spans[1].status == "success"
        assert trace.spans[2].status == "success"
        assert trace.spans[3].status == "error"
        assert trace.spans[3].error_description == "FM invocation timed out"
        assert trace.review_status == "error"

    def test_stage_attributes_resource_and_findings_counts(self):
        """Record resource_count and findings_count as stage attributes."""
        trace = start_review_trace()

        with trace_stage("parse", {"resource_count": 15}):
            pass

        with trace_stage("static_analysis") as span:
            span.attributes["findings_count"] = 4
            span.attributes["passed_checks"] = 11

        parse_span = trace.get_span("parse")
        static_span = trace.get_span("static_analysis")

        assert parse_span.attributes["resource_count"] == 15
        assert static_span.attributes["findings_count"] == 4
        assert static_span.attributes["passed_checks"] == 11


# ---------------------------------------------------------------------------
# Pipeline stages constant tests
# ---------------------------------------------------------------------------


class TestPipelineStages:
    """Tests for the PIPELINE_STAGES constant."""

    def test_contains_all_seven_stages(self):
        assert len(PIPELINE_STAGES) == 7

    def test_stages_in_order(self):
        expected = (
            "parse",
            "load_context",
            "static_analysis",
            "semantic_analysis",
            "generate_fixes",
            "compose_response",
            "persist",
        )
        assert PIPELINE_STAGES == expected
