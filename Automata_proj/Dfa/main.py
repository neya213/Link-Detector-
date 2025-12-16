from dfa_keywords import dfa_keywords
from dfa_symbols import dfa_symbols
from dfa_ip import dfa_ip
from dfa_tld import dfa_tld
from dfa_encoded import dfa_encoded


def unified_phishing_detector(url):

    results = {
        "DFA1_keywords": dfa_keywords(url),
        "DFA2_symbols": dfa_symbols(url),
        "DFA3_ip": dfa_ip(url),
        "DFA4_tld": dfa_tld(url),
        "DFA5_encoded": dfa_encoded(url)
    }

    match_count = sum(1 for v in results.values() if v)

    if match_count == 0:
        risk = "SAFE"
    elif 1 <= match_count <= 2:
        risk = "SUSPICIOUS"
    else:
        risk = "HIGH RISK / PHISHING"

    return match_count, results, risk


if __name__ == "__main__":
    print("=== PHISHING DETECTOR DFA MACHINE ===")

    while True:
        url = input("\nEnter a URL to scan: ")

        match_count, indicators, risk = unified_phishing_detector(url)

        print("\n--- RESULTS ---")
        print(f"Matches Found: {match_count}")
        print("Indicators:")
        for name, value in indicators.items():
            print(f"  {name}: {'MATCH' if value else 'NO MATCH'}")

        print("\nFINAL RISK LEVEL:", risk)

        again = input("\nScan another URL? (y/n): ").lower()
        if again != "y":
            print("Exiting DFA Machine...")
            break

