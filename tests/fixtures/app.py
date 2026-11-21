# Sample app — ALL keys below are FAKE test values (TESTFAKE markers /
# a deadbeef hex value for DeepSeek, whose format is 32 hex chars and
# cannot spell TESTFAKE). Used by aiscan selftest / reliability tests.
# Never real credentials. The engine filters example-marked values from
# findings by design; detection of these values is verified via
# scan_line(allow_examples=True) in the selftest, not via findings.
import os

OPENAI_API_KEY = "sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
ANTHROPIC_API_KEY = "sk-ant-api03-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
GEMINI_API_KEY = "AIzaTESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b"
GROQ_API_KEY = "gsk_TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
OPENROUTER_API_KEY = "sk-or-v1-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
# Marked demo value: repeated "deadbeef" is the example-key marker for
# hex-format keys (see detectors.registry.is_example_key).
DEEPSEEK_API_KEY = "sk-deadbeefdeadbeefdeadbeefdeadbeef"
XAI_API_KEY = "xai-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
PERPLEXITY_API_KEY = "pplx-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
HF_TOKEN = "hf_TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
REPLICATE_API_TOKEN = "r8_TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

# The same Anthropic key is also in .mcp.json on purpose: dedup must
# report it once, not twice.
