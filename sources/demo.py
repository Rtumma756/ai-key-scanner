"""Demo source: bundled FAKE leaked findings for --demo internet mode.

Runs the real detection pipeline over in-memory fake files, so the internet
mode works with no credentials and demonstrates the flow end to end. Every
value here is obviously fake (DEMOFAKE markers, or a deadbeef hex value for
DeepSeek, whose format is 32 hex chars and cannot spell DEMOFAKE) and must
never be treated as a real credential.

Example-key filtering: this source sets ``allow_examples = True`` because
its entire content is synthetic demonstration data — the demo exists to
show fake findings. That bypass is scoped to this source only. The same
values as literal text in the repo (sources/demo.py itself, scanned by
the dogfood Action as a local file) ARE filtered, because LocalSource
does not set the flag. The DeepSeek value is marked with a repeated
``deadbeef`` run rather than excluded by path: path exclusion would hide
the problem, and a real key committed in a demo/test file is still a
real leak, so the filter is value-based by design.
"""
from __future__ import annotations

from .base import Source

DEMO_FILES = {
    "demo/leaked-repo/.env": [
        'OPENAI_API_KEY="sk-proj-DEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"',
        'GROQ_API_KEY="gsk_DEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"',
        # Marked demo value: "deadbeef" is the example-key marker for
        # hex-format keys (a specific 8-hex run in a 32-hex key has
        # P ~ 6e-9, so no real key is ever suppressed by it).
        'DEEPSEEK_API_KEY="sk-deadbeefdeadbeefdeadbeefdeadbeef"',
    ],
    "demo/leaked-repo/config.py": [
        'GEMINI_API_KEY = "AIzaDEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4"',
        'OPENROUTER_API_KEY = "sk-or-v1-DEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"',
        'ANTHROPIC_API_KEY = "sk-ant-api03-DEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"',
    ],
    "demo/leaked-repo/.mcp.json": [
        '  "mcpServers": {',
        '    "ai-tools": { "env": {',
        '      "XAI_API_KEY": "xai-DEMOFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"',
        '    } }',
        '  }',
    ],
    "demo/leaked-repo/decoys.txt": [
        'request_id = "550e8400-e29b-41d4-a716-446655440000"',
        'api_key = "your-api-key-here"',
    ],
}


class DemoSource(Source):
    name = "demo"
    # This source's content is synthetic demonstration data, so the
    # example-key filter is bypassed for it. See the module docstring:
    # real scan paths never set this.
    allow_examples = True

    def __init__(self, extra_files=None):
        """extra_files: optional {path: [lines]} of additional FAKE files
        (used by the continuous-scan selftest to plant one new fake key)."""
        self.files = dict(DEMO_FILES)
        if extra_files:
            self.files.update(extra_files)

    def iter_lines(self):
        for path, lines in self.files.items():
            for i, line in enumerate(lines, 1):
                yield (path, i, line, {"source": "demo"})

    @property
    def stats(self) -> dict:
        return {"demo_files": len(self.files)}
