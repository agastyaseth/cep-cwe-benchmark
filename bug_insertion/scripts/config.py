# config.py
"""Configuration constants and a unified prompt template for the LLM baseline test."""

import os
from vllm import SamplingParams # Import SamplingParams here

# --- Directory Configuration ---
BASE_DIR = "/home/aseth7/hwsec/bug_insertion"
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DATA_DIR = os.path.join(BASE_DIR, "data")


# --- Model Configuration ---
# Define the models to be tested
MODELS = ["llama3.1-8b", "gemma3-12b", "gpt4o"]

# Mapping internal model identifiers to actual API/vLLM model names
API_MODEL_NAMES = {
    "gpt4o": "gpt-4o",
    # Ensure these match the model identifiers used by your vLLM instance/installation
    "llama3.1-8b": "meta-llama/Llama-3.1-8B",
    "gemma3-12b": "google/gemma-3-12b-it"
}

# --- vLLM Sampling Configuration ---
# Define sampling parameters for vLLM batch generation
VLLM_SAMPLING_PARAMS = SamplingParams(
    temperature=0.1,
    top_p=0.95,
    max_tokens=2500 # Corresponds to max_output_tokens/num_predict
    # Add other SamplingParams like stop=["..."] if needed
)

# Optional: vLLM engine arguments (if needed for LLM initialization)
# Example: VLLM_ENGINE_ARGS = {"tensor_parallel_size": 1, "gpu_memory_utilization": 0.9}
VLLM_ENGINE_ARGS = {#"gpu_memory_utilization":0.95, 
                    "max_model_len": 24096}


# --- Hardware CWE List for Prompt ---
# Transcribed and summarized from the provided image/context
HARDWARE_CWE_LIST = """
Relevant Hardware CWEs for Context:
- CWE-203: Observable Discrepancy (Timing, power analysis, etc., reveals internal state)
- CWE-226: Sensitive Information Not Removed Before Reuse (Uncleared registers/memory)
- CWE-276: Incorrect Default Permissions (Insecure default access controls)
- CWE-319: Cleartext Transmission of Sensitive Information (Unencrypted data on external interfaces)
- CWE-325: Missing Cryptographic Step (Omitting rounds, S-boxes, permutations, etc.)
- CWE-440: Expected Behavior Violation (Incorrect algorithm implementation, logic errors)
- CWE-441: Unintended Proxy / Confused Deputy (Module accesses unauthorized resources via another module)
- CWE-1191: On-Chip Debug/Test Interface Improper Access Control (JTAG, debug ports expose sensitive data/control)
- CWE-1240: Risky Cryptographic Implementation (Using flawed algorithms or weak parameters)
- CWE-1244: Internal Asset Exposed to Unsafe Debug Level (Debug modes reveal internal state)
- CWE-1262: Register Interface Allows Improper Software Access (CPU can read/write security-critical hardware state)
- CWE-1272: Sensitive Information Uncleared Before Debug/Power State Transition (Data persists across resets/power modes)
- CWE-1300: Improper Protection Against Hardware Reverse Engineering (Lack of obfuscation, IP theft risk)
"""

# --- Unified Prompt Template ---
# Template expects 'cwe_list', 'example_analysis', and 'rtl_code' to be formatted in.
# NOTE: Removed model-specific templates.
GENERIC_PROMPT_TEMPLATE = """You are a hardware security expert specializing in identifying Common Weakness Enumeration (CWE) vulnerabilities in RTL code.

Your task is to analyze the provided Verilog RTL file and:
1. Identify the specific hardware CWE vulnerability present in the code, referencing the list below.
2. Specify the exact line numbers or code sections where the vulnerability exists.
3. Explain why this is a vulnerability and how it could potentially be exploited.
4. Provide the specific CWE ID (e.g., CWE-1234) that best matches this vulnerability from the list.

Respond with a structured analysis that clearly identifies the vulnerability, its location, explanation, and the corresponding CWE ID, following the format shown in the example below.

--- Relevant Hardware CWE List ---
{cwe_list}
----------------------------------

--- Example Analysis ---
{example_analysis}
----------------------

Now, analyze the following RTL code:

```verilog
{rtl_code}
```

Provide your analysis in the same structured format as the example, ensuring the identified CWE ID is from the provided list.
"""


# --- Other Configuration ---
MAX_EXAMPLE_RTL_LENGTH = 15000
DEFAULT_EXAMPLE_BUG_ID = 2
DEFAULT_EXAMPLE_LOCATION = "Lines N/A"

# API Timeouts (seconds) - Timeout for OpenAI API call
OPENAI_TIMEOUT = 120

# Request Delays (seconds) - Only used for sequential API calls like OpenAI
OPENAI_DELAY = 2.0
