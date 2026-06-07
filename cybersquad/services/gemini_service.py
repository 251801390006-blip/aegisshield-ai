"""
Cyber Squad AI – Gemini AI Summary Service
"""

import logging
import requests
from flask import current_app

logger = logging.getLogger(__name__)


def get_ai_summary(scan_type: str, input_data: str, result_data: dict) -> str:
    """
    Generate a real-time, professional AI summary.
    Attempts to call Gemini API if GEMINI_API_KEY is configured.
    Otherwise, falls back to a highly polished local heuristic summary.
    """
    api_key = current_app.config.get("GEMINI_API_KEY")
    
    if api_key:
        try:
            summary = _call_gemini_api(api_key, scan_type, input_data, result_data)
            if summary:
                return summary
        except Exception as e:
            logger.warning(f"Failed to generate Gemini summary: {e}. Falling back to local summary.")
            
    return get_local_summary(scan_type, input_data, result_data)


def _call_gemini_api(api_key: str, scan_type: str, input_data: str, result_data: dict) -> str | None:
    """Call the Google Gemini API to generate the summary."""
    prompt = _construct_prompt(scan_type, input_data, result_data)
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 300
        }
    }
    
    # Set a reasonable timeout so it doesn't freeze the page request
    response = requests.post(url, json=payload, headers=headers, timeout=5.0)
    
    if response.status_code == 200:
        data = response.json()
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
            return text
        except (KeyError, IndexError):
            logger.warning("Unexpected response structure from Gemini API.")
            return None
    else:
        logger.warning(f"Gemini API returned status code {response.status_code}: {response.text}")
        return None


def _construct_prompt(scan_type: str, input_data: str, result_data: dict) -> str:
    """Build the prompt for the Gemini model."""
    intro = (
        "You are an expert cybersecurity AI analyst at Cyber Squad. "
        "Analyze the following security scan result and write a professional, concise, and actionable summary (2-3 sentences max). "
        "Do not include greeting or intro text; start directly with the analysis. Use markdown formatting.\n\n"
    )
    
    if scan_type == "spam":
        prompt = (
            f"{intro}"
            f"Scan Category: Spam Email Detection\n"
            f"Input Email Content: \"{input_data}\"\n"
            f"Result: {result_data.get('result')} (Spam or Safe)\n"
            f"Confidence Score: {result_data.get('confidence')}%\n"
            f"Identified Suspicious Indicators: {result_data.get('indicators')}\n\n"
            "Summarize the threat level, explain why it was flagged based on the indicators, and recommend what the user should do next (e.g. discard, do not click)."
        )
    elif scan_type == "phishing":
        prompt = (
            f"{intro}"
            f"Scan Category: Phishing URL Scanner\n"
            f"Input URL: \"{input_data}\"\n"
            f"Result: {result_data.get('result')} (Phishing or Safe)\n"
            f"Threat Risk Score: {result_data.get('risk_score')}/100\n"
            f"Identified Suspicious Indicators: {result_data.get('indicators')}\n\n"
            "Analyze the domain's structure, explain why the model flagged it (e.g., brand-spoofing, IP usage, insecure connection), and advise the user on the danger of visiting the page."
        )
    elif scan_type == "password":
        prompt = (
            f"{intro}"
            f"Scan Category: Password Strength Analyzer\n"
            f"Result Level: {result_data.get('result')} (Very Weak to Very Strong)\n"
            f"Strength Score: {result_data.get('score')}/100\n"
            f"Entropy: {result_data.get('entropy')} bits\n"
            f"Estimated Crack Time: {result_data.get('crack_time')}\n"
            f"Triggered Vulnerability Heuristics: {result_data.get('characteristics')}\n"
            f"Specific Security Recommendations: {result_data.get('recommendations')}\n\n"
            "Explain the strength rating, evaluate the vulnerability of the password to dictionary/brute-force attacks, and outline key action points to improve it."
        )
    elif scan_type == "malware":
        prompt = (
            f"{intro}"
            f"Scan Category: Static Malware Analyzer\n"
            f"Filename: \"{result_data.get('filename')}\"\n"
            f"File Extension: \"{result_data.get('extension')}\"\n"
            f"File Size: {result_data.get('file_size_human')}\n"
            f"Result Risk Level: {result_data.get('result')} (Low to Critical)\n"
            f"Hazard Score: {result_data.get('risk_score')}/100\n"
            f"File Content Signatures/Heuristics: {result_data.get('indicators')}\n\n"
            "Summarize the potential risk of opening this file, explain why it was flagged (e.g. double extension, header mismatch, obfuscated script keywords), and provide clear containment instructions."
        )
    else:
        prompt = f"Summarize the following scan data: {result_data}"
        
    return prompt


def get_local_summary(scan_type: str, input_data: str, result_data: dict) -> str:
    """Generate a highly polished, professional local heuristic summary."""
    if scan_type == "spam":
        is_spam = result_data.get("is_threat", False)
        confidence = result_data.get("confidence", 0)
        indicators = result_data.get("indicators", [])
        
        summary = f"This email is classified as **{'SPAM' if is_spam else 'SAFE'}** with an analysis confidence score of **{confidence}%**."
        if is_spam:
            summary += " The ensemble model detected pattern signatures common in spam and malicious social engineering."
            if "Money/prize offer detected" in indicators:
                summary += " Specifically, it contains unsolicited monetary or lottery reward incentives."
            if "Urgency language detected" in indicators:
                summary += " It utilizes urgency pressure tactics to compel immediate action."
            if "Contains suspicious URL" in indicators:
                summary += " The content contains embedded links targeting suspicious landing pages."
            summary += " **Recommendation:** Do not reply, click any link, or download attachments; permanently delete the email."
        else:
            summary += " The email structure is clean and matches legitimate business or personal correspondence, showing normal character layouts and lacking marketing/phishing flags."
            
    elif scan_type == "phishing":
        is_phishing = result_data.get("is_threat", False)
        risk_score = result_data.get("risk_score", 0)
        indicators = result_data.get("indicators", [])
        domain = result_data.get("domain", "")
        
        summary = f"The URL is classified as **{'PHISHING' if is_phishing else 'SAFE'}** with a computed threat hazard rating of **{risk_score}/100**."
        if is_phishing:
            summary += f" Multiple structural anomalies were detected on the domain **{domain}**."
            if "IP address used instead of domain name" in indicators:
                summary += " The URL bypasses standard DNS registration by routing directly through a raw IP address."
            if "Domain mimics a trusted brand name" in indicators:
                summary += " It uses visual brand-spoofing characteristics targeting brand impersonation."
            if "Insecure HTTP connection (no HTTPS)" in indicators:
                summary += " The site does not use SSL/TLS encryption, making credentials entry extremely unsafe."
            summary += " **Action Required:** Do not visit this site; entering credentials on this host carries a critical threat of account hijacking."
        else:
            summary += f" The address structure matches standard safe practices. The domain (**{domain}**) utilizes standard HTTPS protocols and exhibits low structural entropy without brand-mimicking indicators."
            
    elif scan_type == "password":
        strength = result_data.get("strength", "MODERATE")
        score = result_data.get("score", 50)
        crack_time = result_data.get("crack_time", "Instantly")
        entropy = result_data.get("entropy", 0)
        chars = result_data.get("characteristics", {})
        
        summary = f"This password has a **{strength}** rating with a complexity score of **{score}/100** and an entropy level of **{entropy} bits**."
        if score < 40:
            summary += f" It is highly vulnerable to dictionary and brute-force cracking. Crack time is estimated to be **{crack_time}**."
            reasons = []
            if chars.get("is_common_password"): reasons.append("found in common word lists")
            if chars.get("has_sequential_chars"): reasons.append("contains sequential runs (e.g. abc/123)")
            if chars.get("has_keyboard_pattern"): reasons.append("uses keyboard patterns (e.g. qwerty)")
            if len(reasons) > 0:
                summary += " The password is weak because it " + ", ".join(reasons) + "."
            summary += " **Recommendation:** Increase length to 12+ characters, and mix uppercase, numbers, and symbols."
        elif score < 80:
            summary += f" It offers moderate security against standard attacks, but remains crackable (estimated time: **{crack_time}**). Adding special characters or increasing length will make it extremely secure."
        else:
            summary += " The password has excellent entropy and strong character distribution. It resists brute-force and dictionary attacks effectively, with an estimated crack time of **Centuries**."
            
    elif scan_type == "malware":
        risk_level = result_data.get("risk_level", "LOW")
        score = result_data.get("risk_score", 0)
        ext = result_data.get("extension", "")
        indicators = result_data.get("indicators", [])
        
        summary = f"This file is classified as **{risk_level}** risk with a threat index score of **{score}/100**."
        if risk_level in {"CRITICAL", "HIGH"}:
            summary += f" Static analysis flagged high-threat indicators in this **{ext}** file."
            if any("Double extension" in i for i in indicators):
                summary += " A double-extension masquerade technique is present, indicating deliberate evasion."
            if any("MZ header" in i for i in indicators):
                summary += " Executable code blocks were detected disguised within a non-executable format."
            summary += " **Warning:** Executing or opening this file carries a severe risk of backdoor injection or ransomware. Do not open."
        elif risk_level == "MEDIUM":
            summary += f" The file has a medium risk profile ({ext}). While not confirmed malicious, files of this type (e.g. documents, script files, compressed packages) can carry embedded macros or scripts. Verify the sender."
        else:
            summary += f" No anomalous signatures or executable structures were found. The file extension ({ext}) and size comply with safe usage guidelines. Exercise standard precaution."
    else:
        summary = f"Scan completed successfully with result: {result_data.get('result', 'UNKNOWN')}"
        
    return summary
