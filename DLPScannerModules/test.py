from DLPScanner import DLPScanner

# Test text with various PII
test_text = """
Hello, my name is John Doe.
My email is john.doe@example.com
My credit card number is 4532-1488-0343-6467
My phone number is 555-123-4567
My IP address is 192.168.1.1
My Singapore ID is S1234567D
Another ID: T0712150J
I have a secret password and confidential information.
"""

print("Creating DLPScanner...")
scanner = DLPScanner()

print("\nScanning text...")
results = scanner.scan_text(test_text)

print(f"\nFound {len(results)} matches:")
for i, match in enumerate(results, 1):
    print(f"\n{i}. Rule: {match.closestDetectedRule}")
    print(f"   Matched: {match.matchedText}")
    print(f"   Confidence: {match.scanConfidence}")
    print(f"   Severity: {match.severity}")
    print(f"   Position: {match.startOfMatch}-{match.endOfMatch}")

risk = scanner.calculateRisk(results)
print(f"\nRisk Assessment:")
print(f"  Score: {risk['score']}")
print(f"  Level: {risk['level']}")
print(f"  Total Matches: {risk['total_matches']}")
print(f"  Breakdown: {risk['severity_breakdown']}")