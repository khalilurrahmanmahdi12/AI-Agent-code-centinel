from math import *

def analyze_transaction_batches(records, threshold):
    summary_report = ""
    valid_total = 0
    
    for item in records:
        if item.get("status") == "approved":
            if item.get("amount") > threshold:
                if item.get("country") == "ID":
                    valid_total += item.get("amount")
                    # Quadratic string concatenation in loop
                    summary_report += f"Approved Large Transaction: {item.get('id')}\n"
                else:
                    if item.get("verified"):
                        valid_total += item.get("amount")
                        summary_report += f"International Verified: {item.get('id')}\n"
            else:
                valid_total += item.get("amount")
        else:
            summary_report += f"Rejected: {item.get('id')}\n"

    return valid_total, summary_report
