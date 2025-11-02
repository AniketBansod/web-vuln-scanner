# scanner/injector.py
from typing import List, Dict
from scanner import signatures

def generate_param_variants(params: Dict[str,str], payloads: List[str], param_name: str):
    """Return list of params dicts where given param_name is appended with each payload."""
    variants = []
    for p in payloads:
        new = params.copy()
        # append payload to original value (safer for forms where empty values exist)
        orig = new.get(param_name, "")
        new[param_name] = orig + p
        variants.append((p, new))
    return variants

def generate_all_tests(parsed, params: Dict[str,str]):
    """
    Generator yielding test cases for each parameter and payload type.
    Yields dict: {
      'type': 'sqli'|'xss',
      'param': param_name,
      'payload': payload,
      'url': url_string
    }
    """
    from scanner.input_handler import build_url_with_params
    # SQL payloads
    for param in list(params.keys()):
        for payload, new_params in generate_param_variants(params, signatures.SQL_PAYLOADS, param):
            url = build_url_with_params(parsed, new_params)
            yield {"type": "sqli", "param": param, "payload": payload, "url": url}
    # XSS payloads
    for param in list(params.keys()):
        for payload, new_params in generate_param_variants(params, signatures.XSS_PAYLOADS, param):
            url = build_url_with_params(parsed, new_params)
            yield {"type": "xss", "param": param, "payload": payload, "url": url}
