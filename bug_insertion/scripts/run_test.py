#!/usr/bin/env python3
# run_test.py
"""
Main script to run the baseline testing framework for Hardware CWE Bug Detection.
Uses vLLM batch processing for specified local models and a unified prompt.
"""

import os
import json
import time
import argparse
import gc # For garbage collection after unloading vLLM model
from datetime import datetime
from tqdm import tqdm

# Import functions/variables from other modules
import config
import data_loader
import llm_clients # Now only contains query_gpt4o (if used)
import evaluation

# Try importing vLLM, handle error if not installed
try:
    from vllm import LLM, SamplingParams
    VLLM_AVAILABLE = True
except ImportError:
    VLLM_AVAILABLE = False
    LLM, SamplingParams = None, None # Define as None if import fails
    print("Warning: vLLM library not found. Testing vLLM models will be skipped.")
    print("Please install vLLM (pip install vllm) to test local models.")


def run_baseline_tests(dataset, cwe_dict, example_analysis, models_to_test=None):
    """Runs baseline tests on the specified models using a unified prompt."""
    if models_to_test is None:
        models_to_test = config.MODELS

    # Ensure results directory exists
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    print(f"Results will be saved in: {config.RESULTS_DIR}")

    results = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # --- Separate models by type ---
    openai_models = [m for m in models_to_test if m == "gpt4o"]
    vllm_models = [m for m in models_to_test if m in config.API_MODEL_NAMES and m != "gpt4o"] # Find vLLM models configured

    # --- Prepare the static parts of the prompt once ---
    # This is the main template structure, needs {rtl_code} filled in per item
    generic_prompt_base = config.GENERIC_PROMPT_TEMPLATE

    # --- Process OpenAI Models (Sequentially) ---
    for model_id in openai_models:
        if model_id not in config.MODELS or model_id not in config.API_MODEL_NAMES:
            print(f"Warning: Skipping unrecognized/unconfigured OpenAI model ID '{model_id}'.")
            continue

        print(f"\n--- Testing model: {model_id} (OpenAI API) ---")
        model_results = []
        start_time = time.time()

        for item in tqdm(dataset, desc=f"Processing with {model_id}"):
            bug_id = item.get('bug_id')
            rtl_code = item.get('verilog_content')

            if bug_id is None or rtl_code is None: continue # Skip invalid items
            try: bug_id = int(bug_id)
            except (ValueError, TypeError): continue

            # Format the final prompt for this item
            final_prompt = generic_prompt_base.format(
                cwe_list=config.HARDWARE_CWE_LIST,
                example_analysis=example_analysis,
                rtl_code=rtl_code
            )
            print(f"Final prompt for bug_id {bug_id}: {final_prompt}")

            # Query the model
            response = llm_clients.query_gpt4o(final_prompt) # Pass the fully formatted prompt
            print(f"Response for bug_id {bug_id}: {response}")
            # Evaluate
            if bug_id not in cwe_dict:
                 print(f"Warning: bug_id {bug_id} not found in cwe_dict. Cannot evaluate.")
                 eval_result = {'bug_id': bug_id, 'error': 'bug_id not found in cwe_dict', 'response': response}
            else:
                 eval_result = evaluation.evaluate_response(response, bug_id, cwe_dict)
            model_results.append(eval_result)

            time.sleep(config.OPENAI_DELAY) # Delay between API calls

        end_time = time.time()
        print(f"Finished testing {model_id} in {end_time - start_time:.2f} seconds.")
        results[model_id] = _summarize_and_save_results(model_id, model_results, timestamp)


    # --- Process vLLM Models (Batch Mode) ---
    if not VLLM_AVAILABLE and vllm_models:
         print("\nSkipping vLLM models as vLLM library is not installed.")
    elif vllm_models:
        for model_id in vllm_models:
            if model_id not in config.MODELS or model_id not in config.API_MODEL_NAMES:
                print(f"Warning: Skipping unrecognized/unconfigured vLLM model ID '{model_id}'.")
                continue

            print(f"\n--- Testing model: {model_id} (vLLM Batch) ---")
            model_results = []
            start_time = time.time()
            llm = None # Initialize llm variable

            try:
                # --- 1. Prepare Batch ---
                prompts_batch = []
                items_batch = [] # To store corresponding items/bug_ids

                print("Preparing batch prompts...")
                for item in tqdm(dataset, desc=f"Preparing prompts for {model_id}"):
                    bug_id = item.get('bug_id')
                    rtl_code = item.get('verilog_content')
                    if bug_id is None or rtl_code is None: continue
                    try: int(bug_id) # Validate bug_id
                    except (ValueError, TypeError): continue

                    # Format the final prompt for this item
                    final_prompt = generic_prompt_base.format(
                        cwe_list=config.HARDWARE_CWE_LIST,
                        example_analysis=example_analysis,
                        rtl_code=rtl_code
                    )
                    prompts_batch.append(final_prompt)
                    items_batch.append(item)

                if not prompts_batch:
                    print(f"No valid prompts generated for model {model_id}. Skipping.")
                    continue

                # --- 2. Initialize vLLM ---
                vllm_model_name = config.API_MODEL_NAMES[model_id]
                print(f"Initializing vLLM for model: {vllm_model_name}...")
                init_start_time = time.time()
                llm = LLM(model=vllm_model_name, **config.VLLM_ENGINE_ARGS)
                print(f"vLLM initialized in {time.time() - init_start_time:.2f} seconds.")
                # print the first prompt for debugging
                print(f"First prompt for batch: {prompts_batch[0]}")
                # print the first item for debugging
                print(f"First item for batch: {items_batch[0]}")
                # --- 3. Generate Batch ---
                print(f"Generating {len(prompts_batch)} responses in batch...")
                gen_start_time = time.time()
                outputs = llm.generate(prompts_batch, config.VLLM_SAMPLING_PARAMS, use_tqdm=True)
                print(f"Batch generation completed in {time.time() - gen_start_time:.2f} seconds.")

                # --- 4. Process Batch Results ---
                print("Processing and evaluating batch results...")
                results_reliable = len(outputs) == len(items_batch)
                if not results_reliable:
                    print(f"Error: Mismatch between number of prompts ({len(items_batch)}) and vLLM outputs ({len(outputs)}). Results may be incorrect.")

                for i, output in enumerate(outputs):
                    # Ensure index is valid for items_batch in case of mismatch
                    if i >= len(items_batch):
                         print(f"Warning: Skipping output {i+1} due to prompt/output count mismatch.")
                         continue

                    item = items_batch[i]
                    bug_id = int(item['bug_id'])
                    response_text = output.outputs[0].text if output.outputs else "Error: No output generated by vLLM"

                    # Evaluate the response
                    if bug_id not in cwe_dict:
                         print(f"Warning: bug_id {bug_id} not found in cwe_dict. Cannot evaluate.")
                         eval_result = {'bug_id': bug_id, 'error': 'bug_id not found in cwe_dict', 'response': response_text}
                    else:
                         eval_result = evaluation.evaluate_response(response_text, bug_id, cwe_dict)

                    if not results_reliable:
                         eval_result['warning'] = "Result mapping potentially unreliable due to prompt/output count mismatch."
                    model_results.append(eval_result)

                end_time = time.time()
                print(f"Finished testing {model_id} in {end_time - start_time:.2f} seconds (including init & batch gen).")
                results[model_id] = _summarize_and_save_results(model_id, model_results, timestamp)

            except Exception as e:
                print(f"\nError during vLLM processing for model {model_id}: {e}")
                results[model_id] = {
                    'model_id': model_id, 'error': f"Failed during vLLM processing: {e}",
                    'detailed_results': [], 'accuracy': 0, 'correct_detections': 0,
                    'total_evaluated_samples': 0, 'total_processed_items': 0
                 }
                _save_results(model_id, results[model_id], timestamp) # Save error state

            finally:
                 if llm is not None:
                      print(f"Cleaning up vLLM instance for {model_id}...")
                      del llm
                      gc.collect()
                      print("Cleanup complete.")

    # --- Save Overall Summary ---
    _save_overall_summary(results, timestamp)
    return results


# --- Helper Functions (Unchanged from previous version) ---
def _summarize_and_save_results(model_id, model_results, timestamp):
    """Helper function to calculate metrics, format summary, and save."""
    evaluated_results = [res for res in model_results if 'error' not in res]
    correct_detections = sum(1 for result in evaluated_results if result.get('cwe_detected', False))
    total_samples = len(evaluated_results)
    accuracy = correct_detections / total_samples if total_samples > 0 else 0

    model_summary = {
        'model_id': model_id,
        'api_model_name': config.API_MODEL_NAMES.get(model_id, "N/A"),
        'timestamp': timestamp,
        'accuracy': accuracy,
        'correct_detections': correct_detections,
        'total_evaluated_samples': total_samples,
        'total_processed_items': len(model_results),
        'detailed_results': model_results # Contains all items, including errors
    }

    _save_results(model_id, model_summary, timestamp)

    # Print summary for this model
    print(f"{model_id} Accuracy: {accuracy:.2f} ({correct_detections}/{total_samples})")
    if len(model_results) != total_samples:
         print(f"  ({len(model_results) - total_samples} items had evaluation errors)")

    return model_summary

def _save_results(model_id, model_summary, timestamp):
     """Helper function to save individual model results."""
     results_file = os.path.join(config.RESULTS_DIR, f"{model_id}_results_{timestamp}.json")
     try:
         with open(results_file, 'w', encoding='utf-8') as f:
             json.dump(model_summary, f, indent=2, ensure_ascii=False)
         print(f"Results for {model_id} saved to {results_file}")
     except Exception as e:
          print(f"Error saving results for {model_id} to {results_file}: {e}")

def _save_overall_summary(results, timestamp):
    """Helper function to save the overall summary."""
    overall_summary_data = {
        'timestamp': timestamp,
        'models_tested': list(results.keys()),
        'summary': {
            model: {
                'accuracy': res.get('accuracy', 0), # Use .get for safety if model failed
                'correct_detections': res.get('correct_detections', 0),
                'total_evaluated_samples': res.get('total_evaluated_samples', 0)
            } for model, res in results.items()
        }
    }
    overall_file = os.path.join(config.RESULTS_DIR, f"overall_summary_{timestamp}.json")
    try:
        with open(overall_file, 'w', encoding='utf-8') as f:
            json.dump(overall_summary_data, f, indent=2, ensure_ascii=False)
        print(f"\nOverall summary saved to {overall_file}")
    except Exception as e:
         print(f"Error saving overall summary to {overall_file}: {e}")


# --- Main Execution Block (Unchanged from previous version) ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run baseline tests for hardware CWE bug detection.")
    default_dataset_path = os.path.join(config.DATA_DIR, "buggy_rtl_dataset.json")
    default_cwe_list_path = os.path.join(config.DATA_DIR, "CWE-Buglist.csv")

    parser.add_argument("--dataset", default=default_dataset_path,
                        help=f"Path to the buggy RTL dataset JSON file (default: {default_dataset_path})")
    parser.add_argument("--cwe-list", default=default_cwe_list_path,
                        help=f"Path to the CWE bug list CSV file (default: {default_cwe_list_path})")
    parser.add_argument("--models", nargs="+", choices=config.MODELS, default=config.MODELS,
                        help=f"Models to test (default: {config.MODELS})")
    parser.add_argument("--example-bug-id", type=int, default=config.DEFAULT_EXAMPLE_BUG_ID,
                        help=f"Bug ID from the dataset to use as the prompt example (default: {config.DEFAULT_EXAMPLE_BUG_ID})")
    parser.add_argument("--results-dir", default=config.RESULTS_DIR,
                        help=f"Directory to save result files (default: {config.RESULTS_DIR})")
    parser.add_argument("--data-dir", default=config.DATA_DIR,
                        help=f"Directory containing data files (default: {config.DATA_DIR})")

    args = parser.parse_args()

    # Override config directories if specified via CLI
    config.RESULTS_DIR = args.results_dir
    config.DATA_DIR = args.data_dir

    # Load data
    print(f"Loading dataset from: {args.dataset}")
    dataset = data_loader.load_dataset(args.dataset)
    if dataset is None: exit(1)

    print(f"Loading CWE list from: {args.cwe_list}")
    cwe_dict = data_loader.load_cwe_list(args.cwe_list)
    if cwe_dict is None: exit(1)

    # Generate example analysis string
    print(f"Generating example analysis using Bug ID: {args.example_bug_id}")
    example_analysis = data_loader.get_example_analysis_string(dataset, cwe_dict, args.example_bug_id)
    if not example_analysis: # Check if empty string was returned on error
        print("Error: Failed to generate example analysis string.")
        exit(1)

    # Run tests
    print("\nStarting baseline tests...")
    results = run_baseline_tests(dataset, cwe_dict, example_analysis, args.models)

    print("\nBaseline testing completed.")
    if results:
        print("\n--- Overall Summary ---")
        for model_id, summary_data in results.items():
            # Use .get with default 0 for safety in case a model run failed completely
            acc = summary_data.get('accuracy', 0)
            corr = summary_data.get('correct_detections', 0)
            total = summary_data.get('total_evaluated_samples', 0)
            print(f"  {model_id}: Accuracy={acc:.2f} ({corr}/{total})")
        print("---------------------\n")
    else:
        print("No models were successfully tested.")