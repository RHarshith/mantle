"""Protocol for LLM payload parsing and schema application.

Abstracts the logic that converts raw MITM HTTP captures into structured
prompt/response records using configurable LLM API schemas.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ILLMParser(Protocol):
    """Contract for LLM payload parsing operations."""

    def parse_llm_calls_from_mitm(
        self, trace: Any, llm_api_schemas: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Parse MITM logs into turn-level prompt/response records."""
        ...

    def section_values(
        self, data: Any, specs: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Resolve schema section specs to concrete values from payload data."""
        ...

    def normalize_streaming_response_body(self, raw: str) -> dict[str, Any]:
        """Normalize streamed SSE payload into a structured response object."""
        ...

    def normalize_response_body_for_sections(self, response_body: Any) -> dict[str, Any]:
        """Normalize raw response objects before section extraction."""
        ...
