# llm_clients.py
"""Functions to query different Large Language Model APIs."""

import os
import time
import openai # Keep for query_gpt4o
import config # Import config for API model names

# --- OpenAI Client ---
def query_gpt4o(fully_formatted_prompt):
    """Query the GPT-4o API with the fully formatted prompt."""
    api_key = "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"

    try:
        client = openai.OpenAI(api_key=api_key)
        model_name = config.API_MODEL_NAMES.get("gpt4o", "gpt-4o")

        # The prompt is already fully formatted with CWE list, example, and RTL code
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[{"role": "user", "content": fully_formatted_prompt}],
            temperature=0.1,
            max_tokens=2500, # Consider making this configurable
            timeout=config.OPENAI_TIMEOUT
        )
        # Check if response has choices and content
        if response.choices and response.choices[0].message and response.choices[0].message.content:
             return response.choices[0].message.content
        else:
             print(f"Warning: Received empty or unexpected response from GPT-4o: {response}")
             return "Error: Empty or unexpected response from GPT-4o"

    except openai.AuthenticationError:
         print("Error: Invalid OpenAI API key.")
         return "Error: AuthenticationError"
    except openai.RateLimitError:
         print("Error: OpenAI API rate limit exceeded.")
         time.sleep(60)
         return "Error: RateLimitError"
    except openai.APITimeoutError:
        print("Error: OpenAI API request timed out.")
        return "Error: APITimeoutError"
    except openai.APIConnectionError as e:
         print(f"Error: OpenAI API connection issue: {e}")
         return f"Error: APIConnectionError - {e}"
    except Exception as e:
        print(f"Error querying GPT-4o: {e}")
        return f"Error: {str(e)}"

# Note: vLLM query logic moved to run_test.py for batch processing.