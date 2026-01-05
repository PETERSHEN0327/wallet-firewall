from typing import Dict, Any

def extract_features(chain: str, to_address: str, amount: float) -> Dict[str, Any]:
    """
    Feature extraction placeholder.
    """
    return {
        "chain": chain,
        "amount": amount,
        "is_large_tx": amount >= 10000,
    }
