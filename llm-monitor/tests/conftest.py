"""Shared pytest setup for the LLM-Monitor test suite.

The monitor package is laid out flat (``proxy.py``, ``classifier.py`` at the
root of ``llm-monitor/``) rather than as an installed package, so the tests
import it by module name. That only resolves if ``llm-monitor/`` is on
``sys.path``.

Doing that here rather than in an individual test module matters: without it,
``test_proxy_telemetry.py`` only imports when ``test_detection_regressions.py``
happens to be collected first, because that module inserts the path as an import
side effect. Run alone, it failed with ``ModuleNotFoundError: No module named
'proxy'``. Test files must not depend on collection order.
"""

from __future__ import annotations

import sys
from pathlib import Path

MONITOR_ROOT = Path(__file__).resolve().parents[1]

if str(MONITOR_ROOT) not in sys.path:
    sys.path.insert(0, str(MONITOR_ROOT))
