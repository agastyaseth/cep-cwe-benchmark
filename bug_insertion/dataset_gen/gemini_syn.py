import json
import os
import time
# Import the Google Generative AI library and types
from google import genai
from google.genai import types

# --- Configuration ---
MANUAL_DATASET_PATH = '/home/aseth7/hwsec/bug_insertion/data/buggy_rtl_dataset.json' 
SYNTHETIC_DATASET_PATH = '/home/aseth7/hwsec/bug_insertion/data/synthetic_sft_dataset_structured.jsonl' 
GEMINI_API_KEY = '***'

MODEL_NAME = 'gemini-2.0-flash-thinking-exp-01-21'
MAX_RETRIES = 3
RETRY_DELAY = 5 

# --- Configure the Generative AI Client ---
try:
    # Use the Client interface as shown in the user example
    genai_client = genai.Client(api_key=GEMINI_API_KEY)
except Exception as e:
    print(f"Error initializing Gemini Client: {e}")
    exit(1)


def call_gemini_api(prompt):
    """
    Calls the Gemini API using the google-genai library and streaming.

    Args:
        prompt (str): The prompt to send to the Gemini model.

    Returns:
        str: The accumulated text response from the model, or None if an error occurs.
    """
    print(f"\n--- Sending Prompt to Gemini ({MODEL_NAME}) ---")
    # print(prompt) # Keep this commented unless debugging to avoid excessive console output
    print("--------------------------------------------")

    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(text=prompt),
            ],
        ),
    ]
    
    # Configuration for the generation request
    generate_content_config = types.GenerateContentConfig(
        response_mime_type="text/plain",
    )

    try:
        print(f"Calling model {MODEL_NAME} via stream...")
        
        # Use the exact structure from the Google template
        stream = genai_client.models.generate_content_stream(
            model=MODEL_NAME,  # No "models/" prefix
            contents=contents,
            config=generate_content_config,
        )

        accumulated_response = ""
        for chunk in stream:
            if hasattr(chunk, 'text'):
                accumulated_response += chunk.text
            # Print for debugging (optional)
            # print(chunk.text, end="")
            
        print("\n--- Gemini Raw Response (Accumulated) ---")
        # print(accumulated_response) # Keep commented unless debugging
        print("-----------------------------------------")
        
        # Check if the response is empty or blocked
        if not accumulated_response:
             try:
                 if hasattr(stream, 'prompt_feedback') and stream.prompt_feedback.block_reason:
                     print(f"Warning: Response blocked. Reason: {stream.prompt_feedback.block_reason}")
                 else:
                     print("Warning: Received empty response from API.")
             except AttributeError:
                 print("Warning: Received empty response from API (could not check block reason).")
             return None

        return accumulated_response

    except Exception as e:
        print(f"An unexpected error occurred during the Gemini API call: {e}")
        # Log the full exception for debugging if needed
        # import traceback
        # traceback.print_exc()
        return None


def extract_buggy_lines(verilog_content, line_numbers):
    """
    Extracts specific lines of code from the Verilog content.

    Args:
        verilog_content (str): The full Verilog code.
        line_numbers (list[int]): A list of 1-based line numbers to extract.

    Returns:
        str: The extracted lines of code, joined by newlines.
    """
    lines = verilog_content.splitlines()
    extracted = []
    # Adjust line numbers to be 0-based for list indexing
    zero_based_lines = {n - 1 for n in line_numbers}
    for i, line in enumerate(lines):
        if i in zero_based_lines:
            extracted.append(f"L{i+1}: {line}") # Prepend line number for context
    return "\n".join(extracted)

def construct_prompt(bug_entry):
    """
    Constructs a detailed prompt for the Gemini API based on a bug entry,
    requesting CoT reasoning and a JSON output.

    Args:
        bug_entry (dict): A dictionary representing one bug from the manual dataset.

    Returns:
        str: The formatted prompt string.
    """
    filename = bug_entry.get("filename", "N/A")
    bug_details = bug_entry.get("bug_details", {})
    cwe_id = bug_details.get("CWE-ID", "N/A")
    description = bug_details.get("Description", "N/A")
    justification = bug_details.get("Justification", "N/A")
    verilog_content = bug_entry.get("verilog_content", "")
    buggy_line_nums = bug_entry.get("buggy_lines", [])

    buggy_code_snippet = extract_buggy_lines(verilog_content, buggy_line_nums)

    prompt = f"""
You are an expert in hardware security and Verilog RTL design. Your task is to generate synthetic Verilog code snippets that contain specific Common Weakness Enumerations (CWEs) relevant to hardware design, along with your reasoning and justification, formatted as JSON.

**Goal:** Create a *new*, *distinct* but *conceptually similar* Verilog code example exhibiting the same vulnerability described below. Provide your step-by-step reasoning first, followed by a JSON object containing the generated code and related details.

**Context from Manual Dataset:**
* **Filename:** {filename}
* **CWE-ID:** {cwe_id}
* **Description:** {description}
* **Justification:** {justification}

**Example of Buggy Code (Lines {min(buggy_line_nums) if buggy_line_nums else 'N/A'} - {max(buggy_line_nums) if buggy_line_nums else 'N/A'} from {filename}):**
```verilog
{buggy_code_snippet}
```

**Instructions for Generation:**
1.  **Reasoning First:** Before the JSON output, provide a step-by-step Chain-of-Thought (CoT) reasoning explaining how you will approach the task. Describe how you analyzed the request, chose a scenario, introduced the vulnerability, and formatted the output. Start this section with "*Reasoning Process:*".
2.  **Generate JSON Output:** After the reasoning, output a *single* JSON object enclosed in triple backticks (```json ... ```). This JSON object *must* contain the following keys:
    * `reasoning` (string): A copy of the step-by-step reasoning you provided earlier.
    * `description` (string): A concise description of the vulnerability demonstrated in the generated code (similar to the input description).
    * `justification` (string): An explanation of *why* the generated `buggy_code` contains the specified CWE vulnerability and its potential impact (similar to the input justification).
    * `buggy_code` (string): The newly generated, small, self-contained Verilog module or code snippet (e.g., 10-50 lines).
        * This code *must* contain the {cwe_id} vulnerability.
        * Crucially, add a comment `# {cwe_id}` on the line *directly above* each specific line of Verilog code that introduces or constitutes the vulnerability. Do *not* add comments anywhere else.
        * The Verilog code within the JSON string should be properly escaped (e.g., newlines as `\\n`, quotes as `\\"`).
3.  **Vulnerability Consistency:** Ensure the vulnerability introduced in `buggy_code` is the *exact same type* as {cwe_id}.
4.  **Novelty:** The generated `buggy_code` must be a *new* example, not a copy of the provided context.
5.  **Conciseness:** Keep the generated `buggy_code` focused on demonstrating the vulnerability.

**Generate the reasoning followed by the JSON object containing a new Verilog code snippet demonstrating CWE-{cwe_id}:**
"""
    return prompt

def parse_gemini_response(raw_response):
    """
    Parses the raw response from Gemini to extract reasoning and the JSON object.

    Args:
        raw_response (str): The raw string response from the API.

    Returns:
        dict: A dictionary containing the parsed data (reasoning, description,
              justification, buggy_code), or None if parsing fails.
    """
    if not raw_response:
        return None

    try:
        # Attempt to find the JSON block
        # Look for ```json at the start and ``` at the end, potentially with whitespace
        json_match = re.search(r"```json\s*(\{.*?\})\s*```", raw_response, re.DOTALL)

        if not json_match:
             # Fallback: find the first ```json and the last ```
             json_start = raw_response.find('```json')
             json_end = raw_response.rfind('```')

             if json_start == -1 or json_end == -1 or json_start >= json_end:
                 print("Error: Could not find JSON block in the response.")
                 # Print a snippet for debugging
                 print("--- Response Snippet (JSON block not found) ---")
                 print(raw_response[:500] + "..." if len(raw_response) > 500 else raw_response)
                 print("-----------------------------------------------")
                 return None
             # Extract the JSON string (remove backticks and 'json' marker)
             json_string = raw_response[json_start + len('```json'):json_end].strip()
        else:
             json_string = json_match.group(1).strip()


        # Parse the JSON string
        parsed_json = json.loads(json_string)

        # Basic validation of expected keys
        required_keys = ["reasoning", "description", "justification", "buggy_code"]
        if not all(key in parsed_json for key in required_keys):
            print(f"Error: JSON response missing one or more required keys: {required_keys}")
            print(f"Found keys: {list(parsed_json.keys())}")
            return None

        # Add more validation if needed (e.g., check types, non-empty strings)
        if not all(isinstance(parsed_json[key], str) and parsed_json[key] for key in required_keys):
             print(f"Error: One or more required keys in JSON have invalid type or are empty.")
             return None

        return parsed_json

    except json.JSONDecodeError as e:
        print(f"Error: Failed to decode JSON from the response: {e}")
        print("--- Faulty JSON String Snippet ---")
        # Be careful printing potentially large strings
        snippet = json_string[:500] + "..." if len(json_string) > 500 else json_string
        print(snippet)
        print("---------------------------------")
        return None
    except Exception as e:
        # Catch other potential errors during parsing
        print(f"An unexpected error occurred during response parsing: {e}")
        import traceback
        traceback.print_exc() # Print stack trace for unexpected errors
        return None


def main():
    """
    Main function to load data, generate prompts, call API, parse JSON, and save results.
    """
    # --- Load Manual Dataset ---
    script_dir = os.path.dirname(__file__)
    global MANUAL_DATASET_PATH

    try:
        with open(MANUAL_DATASET_PATH, 'r', encoding='utf-8') as f:
            manual_dataset = json.load(f)
        print(f"Successfully loaded {len(manual_dataset)} entries from {MANUAL_DATASET_PATH}")
    except FileNotFoundError:
        print(f"Error: Manual dataset file not found at {MANUAL_DATASET_PATH}")
        print("Ensure the file exists or set the MANUAL_DATASET_PATH environment variable.")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {MANUAL_DATASET_PATH}. Check file format.")
        return
    except Exception as e:
        print(f"An unexpected error occurred while loading the dataset: {e}")
        return

    synthetic_data = []
    examples_per_bug = 30
    total_success = 0
    total_failed = 0
    
    # Open the output file in append mode at the beginning
    output_path = os.environ.get("SYNTHETIC_DATASET_PATH", SYNTHETIC_DATASET_PATH)
    try:
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
    except Exception as e:
        print(f"Warning: Could not ensure output directory exists: {e}")
    
    # --- Process All Bug Entries ---
    for i, bug_entry in enumerate(manual_dataset):
        print(f"\n--- Processing Bug Entry {i+1}/{len(manual_dataset)} (ID: {bug_entry.get('bug_id', 'N/A')}) ---")
        
        # Basic validation of entry structure
        if not all(k in bug_entry for k in ["verilog_content", "bug_details", "buggy_lines"]):
             print(f"Warning: Skipping entry {i+1} due to missing required keys.")
             continue
        if not isinstance(bug_entry.get("bug_details"), dict) or not bug_entry["bug_details"].get("CWE-ID"):
             print(f"Warning: Skipping entry {i+1} due to missing or invalid 'bug_details' or 'CWE-ID'.")
             continue
        
        # Get the CWE and construct the base prompt
        cwe_id = bug_entry["bug_details"]["CWE-ID"]
        prompt = construct_prompt(bug_entry)
        success_count = 0
        
        # Generate multiple examples for this bug
        for j in range(examples_per_bug):
            print(f"\n--- Generating example {j+1}/{examples_per_bug} for bug {i+1} (CWE: {cwe_id}) ---")
            
            # Try with retries
            for attempt in range(MAX_RETRIES):
                raw_response = call_gemini_api(prompt)
                
                if raw_response:
                    # Add a small delay after API call
                    time.sleep(1)
                    
                    parsed_data = parse_gemini_response(raw_response)
                    if parsed_data:
                        # Check if the buggy code contains the expected CWE comment
                        expected_comment = f"# {cwe_id}"
                        if expected_comment in parsed_data.get("buggy_code", ""):
                            # Success - add to our collection
                            print(f"Successfully generated example {j+1} for bug {i+1} (attempt {attempt+1})")
                            
                            # Create the entry
                            entry = {
                                "prompt": prompt,
                                "completion": parsed_data,
                                "metadata": {
                                    "original_bug_id": bug_entry.get('bug_id', f"bug_{i+1}"),
                                    "cwe_id": cwe_id,
                                    "example_number": j+1
                                }
                            }
                            
                            # Add to in-memory collection
                            synthetic_data.append(entry)
                            
                            # Immediately save to output file
                            try:
                                with open(output_path, 'a', encoding='utf-8') as outfile:
                                    json.dump(entry, outfile, ensure_ascii=False)
                                    outfile.write('\n')
                                print(f"Immediately saved example {j+1} for bug {i+1} to output file")
                            except Exception as e:
                                print(f"Warning: Could not save example immediately: {e}")
                            
                            success_count += 1
                            total_success += 1
                            break  # Break retry loop on success
                        else:
                            print(f"Warning: Generated code doesn't contain the expected '{expected_comment}' comment.")
                    else:
                        print(f"Failed to parse response (attempt {attempt+1}/{MAX_RETRIES})")
                else:
                    print(f"API call failed (attempt {attempt+1}/{MAX_RETRIES})")
                
                # If we get here, the current attempt failed
                if attempt < MAX_RETRIES - 1:
                    print(f"Waiting {RETRY_DELAY} seconds before retrying...")
                    time.sleep(RETRY_DELAY)
                else:
                    print(f"Max retries reached for example {j+1}, bug {i+1}")
                    total_failed += 1
            
            # Brief pause between generating examples
            time.sleep(2)
        
        print(f"Completed bug {i+1}: {success_count}/{examples_per_bug} examples successfully generated")
        
        # Save intermediate results after each bug to avoid losing data
        if synthetic_data:
            intermediate_path = os.path.join(script_dir, f"intermediate_results_bug_{i+1}.jsonl")
            try:
                with open(intermediate_path, 'w', encoding='utf-8') as f:
                    for entry in synthetic_data:
                        json.dump(entry, f, ensure_ascii=False)
                        f.write('\n')
                print(f"Saved intermediate results to {intermediate_path}")
            except Exception as e:
                print(f"Error saving intermediate results: {e}")

    # --- Final Report ---
    print(f"\n=== Generation Complete ===")
    print(f"Total successful examples: {total_success}")
    print(f"Total failed examples: {total_failed}")
    print(f"Success rate: {total_success / (total_success + total_failed) * 100:.2f}%")

    # --- Save Final Synthetic Dataset ---
    # Keep this section as a backup/verification that all data was saved correctly
    if synthetic_data:
        try:
            # Count existing entries to verify
            existing_entries = 0
            try:
                if os.path.exists(output_path):
                    with open(output_path, 'r', encoding='utf-8') as f:
                        for _ in f:
                            existing_entries += 1
            except Exception:
                pass
                
            # If the counts don't match, save everything again to ensure completeness
            if existing_entries != len(synthetic_data):
                print(f"Verification failed: Found {existing_entries} entries in file but have {len(synthetic_data)} in memory.")
                print("Saving all entries again to ensure completeness...")
                with open(output_path, 'w', encoding='utf-8') as f:
                    for entry in synthetic_data:
                        json.dump(entry, f, ensure_ascii=False)
                        f.write('\n')
            else:
                print(f"\nVerified all {len(synthetic_data)} entries were correctly saved to {output_path}")
        except Exception as e:
            print(f"Error during final verification: {e}")
    else:
        print("\nNo synthetic data was generated or successfully processed.")

# Need to import re for the updated parse_gemini_response
import re

if __name__ == "__main__":
    main()
