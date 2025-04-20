# evaluation.py
"""Functions for evaluating LLM responses against ground truth."""

def evaluate_response(response, bug_id, cwe_dict):
    """
    Evaluate the model's response against the ground truth CWE ID.

    Returns a dictionary with evaluation metrics.
    NOTE: Basic evaluation checking only for CWE ID string presence.
    """
    ground_truth = cwe_dict.get(bug_id)
    if not ground_truth:
         # This case should ideally be handled before calling evaluate
         print(f"Error in evaluate_response: No ground truth CWE found for bug_id {bug_id}")
         return {
            'bug_id': bug_id,
            'ground_truth_cwe': 'N/A',
            'cwe_detected': False,
            'response': response,
            'error': 'Missing ground truth CWE in evaluation'
         }

    ground_truth_cwe = ground_truth.get('cwe_id', '')
    if not ground_truth_cwe:
        print(f"Warning: Ground truth for bug_id {bug_id} is missing 'cwe_id'.")
        ground_truth_cwe = 'N/A (Missing in Source)'
        cwe_detected = False
    else:
        # Case-insensitive check if response contains the CWE ID (e.g., "CWE-123")
        # Add word boundaries to reduce false positives (e.g., matching "CWE-1234" if looking for "CWE-123")
        import re
        # Simple check for the exact string, case-insensitive
        # Using regex might be slightly more robust if format varies slightly
        # pattern = re.compile(r'\b' + re.escape(ground_truth_cwe) + r'\b', re.IGNORECASE)
        # cwe_detected = bool(pattern.search(response))
        cwe_detected = ground_truth_cwe.lower() in response.lower()


    # Potential future enhancement: Parse response for line numbers and compare
    # detected_lines = parse_line_numbers(response)
    # line_match = compare_lines(detected_lines, ground_truth.get('buggy_lines', []))

    evaluation = {
        'bug_id': bug_id,
        'ground_truth_cwe': ground_truth_cwe,
        'cwe_detected': cwe_detected,
        'response': response # Consider truncating long responses for storage
    }
    return evaluation

# Example placeholder for more advanced parsing (if needed later)
# def parse_line_numbers(response_text):
#     # Implement regex or other parsing to find line numbers mentioned
#     return []

# def compare_lines(detected, ground_truth):
#     # Implement logic to check if detected lines overlap with ground truth
#     return False