import re, os, json
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class DLPMatcher:
    closestDetectedRule: str
    matchedText: str
    scanConfidence: float
    startOfMatch: int
    endOfMatch: int
    contextBeforeAfterMatch: str
    severity: str
    keywordCategory: str = ""
    keywordDescription: str = ""

class DLPScanner:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), "config", "keywords.json")
        self.config = self.load_config()
        self.patterns = self.load_patterns()
        self.keywords = self.load_keywords()
        self.settings = self.config.get("settings", {})
    
    def load_config(self) -> Dict[str, Any]:
        # Load keywords.json file
        try:
            if not os.path.exists(self.config_path):
                self._create_default_config()
            with open(self.config_path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading keyword dictionary: {e}")
            return self._get_default_config()
    
    def _create_default_config(self):
        default_config = self._get_default_config()
        config_dir = os.path.dirname(self.config_path)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        with open(self.config_path, 'w', encoding="utf-8") as f:
            json.dump(default_config, f, indent=4)
    
    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "keywords": {
                "confidential": {
                "severity": "High",
                "description": "Confidential and restricted information",
                "terms": ["confidential","secret","classified","restricted",]
                },

                "financial": {
                "severity": "Critical",
                "description": "Financial and monetary information",
                "terms": ["bank account","credit card","account number","iban",]
                },
                "personal": {
                "severity": "High",
                "description": "Personal identifiable information",
                "terms": ["date of birth","dob","id",]
                },
                "technical": {
                "severity": "Critical",
                "description": "Technical credentials and security information",
                "terms": ["password","api key","secret key","token","private key",]
                },
            },
            "settings": {
                "case_sensitive": False,
                "whole_word_only": True,
                "minimum_confidence": 0.5,
                "context_window": 50
            }
        }

    
    def load_patterns(self) -> Dict[str, str]:
        return {
            "SID": {'regex': re.compile(r"\b[STFGM]\d{7}[A-Z]\b"), 'validate': self._validate_sid, 'severity': 'High'},
            "CreditCard": {'regex': re.compile(r"\b(?:\d[ -]*?){13,16}\b"), 'validate': self._validate_credit_card, 'severity': 'Critical'},
            "PhoneNumber": {'regex': re.compile(r"\b\d{3}[-.\s]??\d{3}[-.\s]??\d{4}\b"), 'validate': None, 'severity': 'Medium'},
            "Email": {'regex': re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), 'validate': None, 'severity': 'Medium'},
            "IPAddress": {'regex': re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 'validate': self._validate_ip_address, 'severity': 'High'},
        }
    
    def load_keywords(self) -> Dict[str, Dict]:
        keywords = {}

        for category, details in self.config.get("keywords", {}).items():
            keywords[category] = {
                "terms": details.get("terms", []),
                "severity": details.get("severity", "Low"),
                "description": details.get("description", ""),
            }
        return keywords
    
    def reload_config(self):
        self.config = self.load_config()
        self.patterns = self.load_patterns()
        self.keywords = self.load_keywords()
        self.settings = self.config.get("settings", {})
    
    def _validate_sid(self, sid: str) -> bool: #example of sid: T0123456A
        digits = re.sub(r'\D', '', sid)
        if len(digits) != 9:
            return False
        
        startAlphabet = digits[0]
        numbers = digits[1:8]
        endAlphabet = sid[-1]

        if startAlphabet not in "STFGM":
            return False
        if not numbers.isdigit():
            return False
        if endAlphabet not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            return False
        
        weights = [2, 7, 6, 5, 4, 3, 2]
        total = sum(int(numbers[i]) * weights[i] for i in range(7))

        if startAlphabet in "ST":
            remainder = total % 11
            checkLetter = "JZIHGFEDCBA"
        else: 
            remainder = (total + 4) % 11
            checkLetter = "XWUTRQPNMLK" 

        return endAlphabet == checkLetter[remainder]
    
    def _validate_credit_card(self, cardNumber: str) -> bool:
        digits = re.sub(r'\D', '', cardNumber)
        if len(digits) < 13 or len(digits) > 16:
            return False
        
        total = 0 #Luhn algorithm for credit card validation
        reverseDigits = digits[::-1]
        for i, digit in enumerate(reverseDigits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0
    
    def _validate_ip_address(self, ip: str) -> bool:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True
    
    def _get_context(self, text: str, start: int, end: int) -> str:
        # Get context around the matched text, just for display purposes
        contextWindow = self.settings.get("context_window", 50)
        startContext = max(0, start - contextWindow)
        endContext = min(len(text), end + contextWindow)
        return text[startContext:endContext]
    
    def scan_text(self, text: str) -> List[DLPMatcher]:
        matches = []
        minConfidence = self.settings.get("minimun_confidence", 0.5)

        for patternName, patternDetails in self.patterns.items():
            for match in patternDetails['regex'].finditer(text):
                matchedText = match.group()
                
                isValid = True
                if patternDetails['validate']:
                    isValid = patternDetails['validate'](matchedText)
                
                if isValid:
                    confidence = 1.0
                    if confidence >= minConfidence:
                        start, end = match.start(), match.end()
                        context = self._get_context(text, start, end)
                        matches.append(DLPMatcher(
                            closestDetectedRule=patternName,
                            matchedText=matchedText,
                            scanConfidence=confidence,
                            startOfMatch=start,
                            endOfMatch=end,
                            contextBeforeAfterMatch=context,
                            severity=patternDetails['severity'],
                        ))
        
        caseSensitive = self.settings.get("case_sensitive", False)
        wholeWordOnly = self.settings.get("whole_word_only", True)

        for category, categoryInfo in self.keywords.items():
            for keyword in categoryInfo['terms']:
                if wholeWordOnly:
                    pattern = r'\b' + re.escape(keyword) + r'\b'
                else:
                    pattern = re.escape(keyword)
                
                upperCaseDeterminer = 0 if caseSensitive else re.IGNORECASE
                patternRegex = re.compile(pattern, upperCaseDeterminer)

                for match in patternRegex.finditer(text):
                    matchedText = match.group()
                    confidence = 0.6
                    if confidence >= minConfidence:
                        start, end = match.start(), match.end()
                        context = self._get_context(text, start, end)
                        matches.append(DLPMatcher(
                            closestDetectedRule=keyword,
                            matchedText=matchedText,
                            scanConfidence=confidence,
                            startOfMatch=start,
                            endOfMatch=end,
                            contextBeforeAfterMatch=context,
                            severity=categoryInfo.get("severity", "Low"),
                            keywordCategory='keyword',
                            keywordDescription=categoryInfo.get("description", keyword)
                        ))
        return matches
    
    def calculateRisk(self, matches: List[DLPMatcher]) -> Dict[str, Any]:
        severityScores = {
            "Critical": 1.0,
            "High": 0.75,
            "Medium": 0.5,
            "Low": 0.25
        }
        totalScore = 0.0
        severityCounts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for match in matches:
            score = severityScores.get(match.severity, 0.0)
            totalScore += score * match.scanConfidence
            severityCounts[match.severity] += 1
        
        maxPossibleScore = len(matches) * max(severityScores.values())
        normalizedScore = (totalScore / maxPossibleScore * 100) if maxPossibleScore > 0 else 0.0
        if normalizedScore >= 80:
            riskLevel = 'Critical'
        elif normalizedScore >= 60:
            riskLevel = 'High'
        elif normalizedScore >= 30:
            riskLevel = 'Medium'
        else:
            riskLevel = 'Low'
    
        return {
            'score': round(normalizedScore, 2),
            'level': riskLevel,
            'total_matches': len(matches),
            'severity_breakdown': severityCounts
        }