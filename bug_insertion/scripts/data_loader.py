# data_loader.py
"""Functions for loading benchmark datasets and CWE information."""

import json
import csv
import config  # Import config for defaults

def load_dataset(dataset_path):
    """Load the dataset of buggy RTL files from a JSON file."""
    try:
        with open(dataset_path, 'r', encoding='utf-8') as f:
            try:
                dataset = json.load(f)
                if not isinstance(dataset, list) or not dataset:
                    print(f"Error: Dataset file '{dataset_path}' is empty or not a valid JSON list.")
                    return None
                return dataset
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON from {dataset_path}: {e}")
                return None
    except FileNotFoundError:
        print(f"Error: Dataset file not found at {dataset_path}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred loading the dataset: {e}")
        return None


def load_cwe_list(cwe_list_path):
    """Load the CWE bug list for reference from a CSV file."""
    cwe_dict = {}
    expected_columns = ['Bug ID', 'CWE-ID', 'Description', 'Justification']
    try:
        with open(cwe_list_path, 'r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            if not all(col in reader.fieldnames for col in expected_columns):
                 print(f"Warning: CSV file '{cwe_list_path}' might be missing expected columns {expected_columns}.")

            for i, row in enumerate(reader):
                try:
                    bug_id_str = row.get('Bug ID', '').strip()
                    cwe_id_str = row.get('CWE-ID', '').strip()

                    if bug_id_str and cwe_id_str:
                        cwe_dict[int(bug_id_str)] = {
                            'cwe_id': cwe_id_str,
                            'description': row.get('Description', '').strip(),
                            'justification': row.get('Justification', '').strip()
                        }
                    else:
                        # Don't print warning for header row if it exists and is skipped
                        if reader.line_num > 1:
                             print(f"Warning: Skipping row {reader.line_num} in {cwe_list_path} due to missing/empty Bug ID or CWE-ID.")
                except (ValueError, TypeError):
                    print(f"Warning: Skipping row {reader.line_num} in {cwe_list_path} due to invalid Bug ID '{bug_id_str}'.")
                except Exception as e:
                    print(f"Warning: Error processing row {reader.line_num} in {cwe_list_path}: {e}")

        if not cwe_dict:
             print(f"Error: No valid CWE data loaded from {cwe_list_path}.")
             return None
        return cwe_dict
    except FileNotFoundError:
        print(f"Error: CWE list file not found at {cwe_list_path}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred loading the CWE list: {e}")
        return None

def get_example_analysis_string(dataset, cwe_dict, example_bug_id=config.DEFAULT_EXAMPLE_BUG_ID):
    """Fetches a specific example and formats it into an analysis string for prompts."""
    if not dataset or not cwe_dict:
        print("Error: Cannot generate example analysis string, dataset or cwe_dict is empty/None.")
        return "" # Return empty string instead of None

    example_item = next((item for item in dataset if item.get('bug_id') == example_bug_id), None)

    if not example_item:
        print(f"Warning: Example bug_id {example_bug_id} not found in dataset. Using first item.")
        example_item = dataset[0]
        example_bug_id = example_item.get('bug_id', 'N/A')

    example_rtl = example_item.get('verilog_content', 'Error: RTL not found')
    example_cwe_details = cwe_dict.get(example_bug_id, {}) if isinstance(example_bug_id, int) else {}
    example_cwe_id = example_cwe_details.get('cwe_id', 'CWE-?')
    example_description = example_cwe_details.get('description', 'Description not found')
    buggy_lines = example_item.get('buggy_lines', [])
    if buggy_lines:
        example_location = f"Lines: {', '.join(map(str, buggy_lines))}"
    else:
        example_location = config.DEFAULT_EXAMPLE_LOCATION
    explanation = example_cwe_details.get('justification', 'No justification provided.')

    # Truncate example RTL if needed
    if len(example_rtl) > config.MAX_EXAMPLE_RTL_LENGTH:
        example_rtl = example_rtl[:config.MAX_EXAMPLE_RTL_LENGTH] + "\\n... (truncated)"

    # Format example without markdown code blocks for RTL
    example_analysis = f"""
**Example RTL Code:**
```verilog
{example_rtl}
```

**Expected Analysis:**
1.  **Vulnerability:** {example_description}
2.  **Location:** {example_location}
3.  **Explanation:** {explanation}
4.  **CWE ID:** {example_cwe_id}
"""
    # Add the closing separator manually if needed in the main template
    # example_analysis += "########################"
    return example_analysis