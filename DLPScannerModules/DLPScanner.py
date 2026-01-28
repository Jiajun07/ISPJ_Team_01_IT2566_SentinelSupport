import re, os, json, math
from typing import List, Dict, Any
from dataclasses import dataclass
from collections import Counter

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False
    print("Presidio not available - using regex patterns only")

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
        self.entropy_settings = self.config.get("entropy_settings", {
            "enabled": True,
            "min_entropy": 3.5,
            "min_length": 8,
            "severity": "High",
            "exclude_common_patterns": [
                r"\b[STFGM]\d{7}[A-Z]\b",   # NRIC
                r"^[0-9]+$",  # Pure numbers
                r"^[a-zA-Z]+$",  # pure letters
                r"^[a-zA-Z\s]+$"  # letters with spaces
            ]
        })
        self.action_handler = self.config.get("action_handler", {
            "denyThreshold": 0.7,
            "criticalCounts": 1,
            "highSeverityCounts": 3,
            "strictMode": True,
            "allowedCategories": []
        })

        if PRESIDIO_AVAILABLE:
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        else:
            self.analyzer = None
    
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
            },
            "entropy_settings": {
                "enabled": True,
                "min_length": 8,
                "min_entropy": 3.5,
                "max_entropy": 7.0,
                "severity": "High",
                "exclude_patterns": [
                    r"\b[STFGM]\d{7}[A-Z]\b",
                    r"^[0-9]+$",
                    r"^[a-zA-Z]+$", 
                    r"^[a-zA-Z\s]+$"
                ]
            },
            "decision_settings": {
                "denyThreshold": 30,
                "criticalCounts": 1,
                "highSeverityCounts": 3,
                "strictMode": False,
                "allowedCategories": ["low_risk"]
            }
        }

    def load_patterns(self) -> Dict[str, str]:
        return {
            "SID": {'regex': re.compile(r"\b[STFGM]\d{7}[A-Z]\b"), 'validate': self._validate_sid, 'severity': 'High'},
            "PhoneNumber": {'regex': re.compile(r"\b\d{3}[-.\s]??\d{3}[-.\s]??\d{4}\b"), 'validate': None, 'severity': 'Medium'},
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
        self.entropy_settings = self.config.get("entropy_settings", {
            "enabled": True,
            "min_length": 8,
            "min_entropy": 3.5,
            "max_entropy": 7.0,
            "severity": "High",
            "exclude_patterns": [
                r"\b[STFGM]\d{7}[A-Z]\b",
                r"^[0-9]+$",
                r"^[a-zA-Z]+$", 
                r"^[a-zA-Z\s]+$"
            ]
        })

    def scan_text(self, text: str) -> List[DLPMatcher]:
        matches = []
        minConfidence = self.settings.get("minimum_confidence", 0.5)
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
        if PRESIDIO_AVAILABLE:
            print("yes again")
            presidio_matches = self.scan_with_presidio(text)
            matches.extend(presidio_matches) 

        #for entropy
        entropy_matches = self.scanEntropy(text)
        matches.extend(entropy_matches) 
        
        return matches
    
    def makeDecision(self, matches: List[DLPMatcher]) -> Dict[str, Any]:
        riskAssessment = self.calculateRisk(matches)
        denyThreshold = self.action_handler.get("denyThreshold", 0.7)
        criticalCounts = self.action_handler.get("criticalCounts", 1)
        highSeverityCounts = self.action_handler.get("highSeverityCounts", 3)
        strictMode = self.action_handler.get("strictMode", True)
        allowedCategories = self.action_handler.get("allowedCategories", [])

        filteredMatches = []
        for match in matches:
            if match.keywordCategory not in allowedCategories:
                filteredMatches.append(match)

        decision = "Processed File is Allowed to be Downloaded"
        reasons = []

        if strictMode and len(filteredMatches) > 0:
            decision = "Processed File is NOT Allowed to be Downloaded"
            reasons.append(f"Processed File is NOT Allowed to be Downloaded")
        elif riskAssessment['severity_breakdown']["High"] >= highSeverityCounts:
            decision = "Processed File is NOT Allowed to be Downloaded"
            reasons.append(f"Processed File is NOT Allowed to be Downloaded")
        elif riskAssessment['severity_breakdown']["Critical"] >= criticalCounts:
            decision = "Processed File is NOT Allowed to be Downloaded"
            reasons.append(f"Processed File is NOT Allowed to be Downloaded")
        elif riskAssessment['score'] >= denyThreshold:
            decision = "Processed File is NOT Allowed to be Downloaded"
            reasons.append(f"Processed File is NOT Allowed to be Downloaded")
        else:
            decision = "Processed File is Allowed to be Downloaded"
            if len(filteredMatches) > 0:
                reasons.append(f"Processed File is Allowed to be Downloaded")
        return {
            "decision": decision,
            "reasons": reasons
        }
    
    def scan_and_decide(self, text: str) -> Dict[str, Any]:
        matches = self.scan_text(text)
        return self.makeDecision(matches)
    
    def scan_ocr_and_decide(self, ocr_text: str) -> Dict[str, Any]:
        matches = self.scanOCRText(ocr_text)
        return self.makeDecision(matches)
    


#============== Sensitive keywords Scanning ===================    
    def _validate_sid(self, sid: str) -> bool: #example of sid: T0123456A
        if len(sid) != 9:
            return False
        startAlphabet = sid[0]
        numbers = sid[1:8]
        endAlphabet = sid[8]

        if startAlphabet not in "STFGM":
            return False
        
        if not numbers.isdigit():
            return False
        
        if endAlphabet not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            return False
        
        weights = [2, 7, 6, 5, 4, 3, 2]
        total = sum(int(numbers[i]) * weights[i] for i in range(7))
        adjustment = 4 if startAlphabet in "TG" else 0
        remainder = (total + adjustment) % 11
        if startAlphabet in "ST":
            checkLetter = "JZIHGFEDCBA"
        else: 
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
    
    def scan_with_presidio(self, text: str) -> List[DLPMatcher]:
        print("=== PRESIDIO SCAN START ===")
        print(f"Analyzer exists: {self.analyzer is not None}")
        if not self.analyzer:
            print("Analyzer is None - returning empty list")
            return []
        matches = []
        print(f"Text to scan (first 200 chars): {text[:200]}")
        print(f"Text length: {len(text)}")

        entities_to_detect = ["CREDIT_CARD", "EMAIL_ADDRESS", "IP_ADDRESS", "PHONE_NUMBER"]
        print(f"Entities to detect: {entities_to_detect}")

        results = self.analyzer.analyze(text=text, entities=entities_to_detect, language='en')
        print(f"Results count: {len(results)}")
        print(f"Results: {results}")

        severity_map = {"CREDIT_CARD": "Critical", "EMAIL_ADDRESS": "Medium", "IP_ADDRESS": "High", "PHONE_NUMBER": "Medium"}
        for result in results:
            print(f"Processing result: {result}")
            if result.score < 0.5:
                print(f"Skipping - score too low: {result.score}")
                continue
            matchedText = text[result.start:result.end]
            context = self._get_context(text, result.start, result.end)
            matches.append(DLPMatcher(
                closestDetectedRule=f"presidio_{result.entity_type}",
                matchedText=matchedText,
                scanConfidence=result.score,
                startOfMatch=result.start,
                endOfMatch=result.end,
                contextBeforeAfterMatch=context,
                severity=severity_map.get(result.entity_type, "Medium"),
                keywordCategory='presidio',
                keywordDescription=f"Presidio detected entity: {result.entity_type}"
            )) 
        print(f"Total matches found: {len(matches)}")
        print("=== PRESIDIO SCAN END ===")
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
    
#================================================================

#==================== Entropy ====================================

    def calculateEntropy(self, text: str) -> float:
        if not text:
            return 0.0
        frequency = Counter(text)
        text_length = len(text)
        entropy = -sum((freq / text_length) * math.log2(freq / text_length) for freq in frequency.values())
        return entropy

    def isHighEntropyString(self, text: str) -> bool:
        if not self.entropy_settings.get("enabled", True):
            return False
        if len(text) < self.entropy_settings.get("min_length", 8):
            return False
        for pattern in self.entropy_settings.get("exclude_common_patterns", []):
            if re.match(pattern, text):
                return False
            
        entropy = self.calculateEntropy(text)
        min_entropy = self.entropy_settings.get("min_entropy", 3.5)
        max_entropy = self.entropy_settings.get("max_entropy", 7.0)
        return min_entropy <= entropy <= max_entropy

    def scanEntropy(self, text: str) -> List[DLPMatcher]:
        matches = []
        if not self.entropy_settings.get("enabled", True):
            return matches
        min_length = self.entropy_settings.get("min_length", 8)
        entropyPattern = r'[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};\'\\:"|<,./<>?]{' + str(min_length) + r',}'

        for pattern in re.finditer(entropyPattern, text):
            pattern2 = pattern.group()
            if self.isHighEntropyString(pattern2):
                entropyValue = self.calculateEntropy(pattern2)
                confidence = min(1.0, entropyValue / self.entropy_settings.get("max_entropy", 7.0))
                start, end = pattern.start(), pattern.end()
                context = self._get_context(text, start, end)
                matches.append(DLPMatcher(
                    closestDetectedRule="High Entropy String",
                    matchedText=pattern2,
                    scanConfidence=confidence,
                    startOfMatch=start,
                    endOfMatch=end,
                    contextBeforeAfterMatch=context,
                    severity=self.entropy_settings.get("severity", "High"),
                    keywordCategory='entropy',
                    keywordDescription='High entropy string detected'
                ))
        return matches
    
#=============================================================

#===================== OCR ===================================
    
    def scanOCRText(self, ocr_text: str) -> List[DLPMatcher]:
        matches = []
        regexMatches = self.scanOCRWithPatterns(ocr_text)
        matches.extend(regexMatches)
        keywordMatches = self.scanOCRWithKeywords(ocr_text)
        matches.extend(keywordMatches)
        if PRESIDIO_AVAILABLE:
            presidioMatches = self.scan_with_presidio(ocr_text)
            matches.extend(presidioMatches)
        entropyMatches = self.scanEntropy(ocr_text)
        matches.extend(entropyMatches)
        return matches
    
    def scanOCRWithPatterns(self, ocr_text: str) -> List[DLPMatcher]:
        matches = []
        minConfidence = self.settings.get("minimum_confidence", 0.5)
    
        for patternName, patternDetails in self.patterns.items():
            for match in patternDetails['regex'].finditer(ocr_text):
                matchedText = match.group()
                isValid = True
                if patternDetails['validate']:
                    isValid = patternDetails['validate'](matchedText)
                if isValid:
                    confidence = 1.0
                    if confidence >= minConfidence:
                        start, end = match.start(), match.end()
                        context = self._get_context(ocr_text, start, end)
                        matches.append(DLPMatcher(
                            closestDetectedRule=f"OCR_{patternName}",
                            matchedText=matchedText,
                            scanConfidence=confidence,
                            startOfMatch=start,
                            endOfMatch=end,
                            contextBeforeAfterMatch=context,
                            severity=patternDetails['severity'],
                            keywordCategory='ocr_pattern',
                            keywordDescription=f"OCR detected pattern: {patternName}"
                        ))
        return matches
    
    def scanOCRWithKeywords(self, ocr_text: str) -> List[DLPMatcher]:
        matches = []
        caseSensitive = self.settings.get("case_sensitive", False)
        wholeWordOnly = self.settings.get("whole_word_only", True)
        minConfidence = self.settings.get("minimum_confidence", 0.5)

        for category, categoryInfo in self.keywords.items():
            for keyword in categoryInfo['terms']:
                if wholeWordOnly:
                    pattern = r'\b' + re.escape(keyword) + r'\b'
                else:
                    pattern = re.escape(keyword)
                upperCaseDeterminer = 0 if caseSensitive else re.IGNORECASE
                patternRegex = re.compile(pattern, upperCaseDeterminer)
                for match in patternRegex.finditer(ocr_text):
                    matchedText = match.group()
                    confidence = 0.6
                    if confidence >= minConfidence:
                        start, end = match.start(), match.end()
                        context = self._get_context(ocr_text, start, end)
                        matches.append(DLPMatcher(
                            closestDetectedRule=f"OCR_{keyword}",
                            matchedText=matchedText,
                            scanConfidence=confidence,
                            startOfMatch=start,
                            endOfMatch=end,
                            contextBeforeAfterMatch=context,
                            severity=categoryInfo.get("severity", "Low"),
                            keywordCategory='ocr_keyword',
                            keywordDescription=f"OCR detected keyword: {keyword}"
                        ))
        return matches
    
    def scanOCRWithPresidio(self, ocr_text: str) -> List[DLPMatcher]:
        matches = []
        entitites_to_detect = ["CREDIT_CARD", "EMAIL_ADDRESS", "IP_ADDRESS", "PHONE_NUMBER"]
        if not self.analyzer:
            return []
        try:
            results = self.analyzer.analyze(text=ocr_text, entities=entitites_to_detect, language='en')
            severity_map = {"CREDIT_CARD": "Critical", "EMAIL_ADDRESS": "Medium", "IP_ADDRESS": "High", "PHONE_NUMBER": "Medium"}
            for result in results:
                if result.score < 0.5:
                    continue
                matchedText = ocr_text[result.start:result.end]
                context = self._get_context(ocr_text, result.start, result.end)
                matches.append(DLPMatcher(
                    closestDetectedRule=f"OCR_presidio_{result.entity_type}",
                    matchedText=matchedText,
                    scanConfidence=result.score,
                    startOfMatch=result.start,
                    endOfMatch=result.end,
                    contextBeforeAfterMatch=context,
                    severity=severity_map.get(result.entity_type, "Medium"),
                    keywordCategory='ocr_presidio',
                    keywordDescription=f"OCR Presidio detected entity: {result.entity_type}"
                ))
        except Exception as e:
            print(f"Error during Presidio analysis: {e}")
        return matches
    
    def scanOCRWithEntropy(self, ocr_text: str) -> List[DLPMatcher]:
        matches = []
        if not self.entropy_settings.get("enabled", True):
            return matches
        min_length = self.entropy_settings.get("min_length", 8)
        entropyPattern = r'[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};\'\\:"|<,./<>?]{' + str(min_length) + r',}'

        for pattern in re.finditer(entropyPattern, ocr_text):
            pattern2 = pattern.group()

            if self.isHighEntropyString(pattern2):
                entropyValue = self.calculateEntropy(pattern2)
                confidence = min(1.0, entropyValue / self.entropy_settings.get("max_entropy", 7.0))
                start, end = pattern.start(), pattern.end()
                context = self._get_context(ocr_text, start, end)
                matches.append(DLPMatcher(
                    closestDetectedRule="OCR_High Entropy String",
                    matchedText=pattern2,
                    scanConfidence=confidence,
                    startOfMatch=start,
                    endOfMatch=end,
                    contextBeforeAfterMatch=context,
                    severity=self.entropy_settings.get("severity", "High"),
                    keywordCategory='ocr_entropy',
                    keywordDescription='OCR High entropy string detected'
                ))
        return matches