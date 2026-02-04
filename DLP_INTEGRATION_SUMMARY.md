# DLP Integration Summary

## Overview
The DLP (Data Loss Prevention) scanner has been integrated into the file upload workflow. When users upload files, the system automatically scans them and displays the sensitivity level before confirming the upload.

## Implementation Details

### 1. New API Endpoint
**Route:** `/scan/dlp/<temp_id>` (GET)
**Location:** `app.py` (lines 625-677)

**What it does:**
- Scans a temporary uploaded file with the DLP scanner
- Extracts text from the file using FileProcessor
- Calculates risk level using DLPScanner
- Maps risk levels to sensitivity classifications
- Returns JSON with risk and sensitivity data

**Risk to Sensitivity Mapping:**
```
Critical → Restricted (Red)
High → Confidential (Orange)
Medium → Internal (Yellow)
Low → Public (Green)
```

### 2. Backend Changes (`app.py`)
- Added `/scan/dlp/<temp_id>` endpoint that:
  - Processes uploaded files to extract text
  - Runs DLP scanner analysis
  - Calculates risk scores (0-100%)
  - Returns sensitivity level and risk details
  - Handles errors gracefully

### 3. Frontend Changes (`templates/confirm_upload.html`)
- **Metadata Display:**
  - Shows sensitivity level (auto-calculated, color-coded)
  - Displays risk score percentage and level
  - Updates in real-time as file is scanned

- **Form Updates:**
  - Sensitivity field is now read-only (set by DLP)
  - Added hidden field `risk_type` that stores the raw risk level (Critical/High/Medium/Low)
  - Risk type is hidden from users but submitted with the form

- **JavaScript:**
  - Automatically triggers DLP scan on page load
  - Fetches scan results from `/scan/dlp/<temp_id>` endpoint
  - Updates UI with sensitivity level and risk score
  - Applies color coding:
    - Red (#d32f2f) for Restricted
    - Orange (#f57c00) for Confidential
    - Yellow (#fbc02d) for Internal
    - Green (#388e3c) for Public

### 4. Hidden Data Fields
- `risk_type`: Stores the actual DLP risk level (Critical/High/Medium/Low)
- This field is submitted with the form but not visible to users
- Used for backend auditing and compliance tracking

## User Experience Flow
1. User uploads file to `/upload/temp`
2. File is temporarily saved
3. User is redirected to `confirm_upload.html`
4. Page automatically loads and:
   - Displays "(scanning...)" message
   - Calls `/scan/dlp/<temp_id>` endpoint
   - Updates sensitivity level based on DLP results
   - Shows risk score percentage
5. User reviews the calculated sensitivity
6. User can modify file name, owner, or notes if needed
7. User clicks "Confirm Upload"
8. Form is submitted with:
   - Auto-calculated sensitivity level
   - Hidden risk_type (for auditing)
   - Other file metadata

## Risk Scoring Algorithm
The DLP scanner uses:
- Keyword matching against configured patterns
- PII detection (credit cards, NRIC, etc.)
- Entropy analysis for high-entropy strings
- Severity scoring (Critical=1.0, High=0.75, Medium=0.5, Low=0.25)
- Confidence weighting for matches
- Normalized score (0-100%)

## Risk Level Determination
- **Critical (≥80%):** Contains multiple critical or high-severity items
- **High (≥60%):** Contains significant sensitive data
- **Medium (≥30%):** Contains some sensitive information
- **Low (<30%):** Minimal or no sensitive data detected

## Error Handling
- If file processing fails: Shows "Error scanning file"
- If no text can be extracted: Defaults to "Public" sensitivity
- Graceful fallback ensures upload workflow continues
