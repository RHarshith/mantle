"""Interface protocols for Mantle.

These Protocol classes define the contracts between components. Write tests
against interfaces first, then add implementations. Implementation modules
may import from here; this package must NEVER import from implementation
modules (capture/, ingest/, analysis/, server/, mantle_agent/).
"""

from mantle.interfaces.capture import ICapture
from mantle.interfaces.llm_parser import ILLMParser
from mantle.interfaces.trace_store import ITraceStore

__all__ = [
    "ITraceStore",
    "ICapture",
    "ILLMParser",
]
