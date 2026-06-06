"""
AegisShield AI – Password Strength Analyzer Service

No ML needed — deterministic rule-based analysis with entropy calculation.
"""

import re
import math
import string


# Character pools
LOWERCASE = set(string.ascii_lowercase)
UPPERCASE = set(string.ascii_uppercase)
DIGITS = set(string.digits)
SPECIAL = set(string.punctuation)

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "admin", "admin123",
    "welcome", "login", "hello", "starwars", "princess", "solo", "master",
}


def analyze_password(password: str) -> dict:
    if not password:
        return {"error": "Empty password provided"}

    length = len(password)
    chars = set(password)

    # Character pool analysis
    has_lower = bool(chars & LOWERCASE)
    has_upper = bool(chars & UPPERCASE)
    has_digit = bool(chars & DIGITS)
    has_special = bool(chars & SPECIAL)

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += 32

    # Entropy in bits
    entropy = length * math.log2(pool_size) if pool_size > 0 else 0

    # Pattern checks
    is_common = password.lower() in COMMON_PASSWORDS
    has_repeated = bool(re.search(r"(.)\1{2,}", password))
    has_sequential = _has_sequential(password)
    has_keyboard = _has_keyboard_walk(password)

    # Score calculation (0–100)
    score = _calculate_score(
        length=length,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_special=has_special,
        entropy=entropy,
        is_common=is_common,
        has_repeated=has_repeated,
        has_sequential=has_sequential,
        has_keyboard=has_keyboard,
    )

    # Crack time estimate
    crack_time = _estimate_crack_time(entropy)

    # Strength label
    if score < 20:
        strength = "VERY WEAK"
        strength_class = "danger"
    elif score < 40:
        strength = "WEAK"
        strength_class = "warning"
    elif score < 60:
        strength = "MODERATE"
        strength_class = "info"
    elif score < 80:
        strength = "STRONG"
        strength_class = "primary"
    else:
        strength = "VERY STRONG"
        strength_class = "success"

    # Recommendations
    recommendations = _get_recommendations(
        length, has_lower, has_upper, has_digit, has_special,
        is_common, has_repeated, has_sequential, has_keyboard
    )

    return {
        "score": score,
        "strength": strength,
        "strength_class": strength_class,
        "entropy": round(entropy, 2),
        "length": length,
        "crack_time": crack_time,
        "characteristics": {
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_special_chars": has_special,
            "is_common_password": is_common,
            "has_repeated_chars": has_repeated,
            "has_sequential_chars": has_sequential,
            "has_keyboard_pattern": has_keyboard,
        },
        "recommendations": recommendations,
        "is_threat": score < 40,
        "risk_score": max(0, 100 - score),
    }


def _calculate_score(length, has_lower, has_upper, has_digit, has_special,
                     entropy, is_common, has_repeated, has_sequential, has_keyboard) -> int:
    score = 0

    # Length scoring (up to 40 pts)
    if length >= 20: score += 40
    elif length >= 16: score += 35
    elif length >= 12: score += 25
    elif length >= 10: score += 18
    elif length >= 8: score += 10
    else: score += 0

    # Character diversity (up to 40 pts)
    if has_lower: score += 8
    if has_upper: score += 10
    if has_digit: score += 10
    if has_special: score += 12

    # Entropy bonus (up to 20 pts)
    if entropy >= 80: score += 20
    elif entropy >= 60: score += 15
    elif entropy >= 40: score += 10
    elif entropy >= 20: score += 5

    # Penalties
    if is_common: score -= 40
    if has_repeated: score -= 10
    if has_sequential: score -= 8
    if has_keyboard: score -= 8

    return max(0, min(100, score))


def _has_sequential(password: str) -> bool:
    pw = password.lower()
    for i in range(len(pw) - 2):
        a, b, c = ord(pw[i]), ord(pw[i+1]), ord(pw[i+2])
        if (b == a + 1 and c == b + 1) or (b == a - 1 and c == b - 1):
            return True
    return False


def _has_keyboard_walk(password: str) -> bool:
    walks = ["qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty", "12345", "09876"]
    pw = password.lower()
    for walk in walks:
        if walk in pw or walk[::-1] in pw:
            return True
    return False


def _estimate_crack_time(entropy: float) -> str:
    """Estimate crack time at 10 billion guesses/second (GPU)."""
    guesses = 2 ** entropy
    seconds = guesses / 1e10

    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 2_592_000:
        return f"{int(seconds / 86400)} days"
    elif seconds < 31_536_000:
        return f"{int(seconds / 2_592_000)} months"
    elif seconds < 3_153_600_000:
        return f"{int(seconds / 31_536_000)} years"
    elif seconds < 3_153_600_000_000:
        return f"{int(seconds / 31_536_000_000)} thousand years"
    else:
        return "Centuries"


def _get_recommendations(length, has_lower, has_upper, has_digit, has_special,
                         is_common, has_repeated, has_sequential, has_keyboard) -> list:
    recs = []
    if is_common:
        recs.append("This is a commonly used password — change it immediately.")
    if length < 12:
        recs.append(f"Increase length to at least 12 characters (currently {length}).")
    if not has_upper:
        recs.append("Add uppercase letters (A–Z) to increase complexity.")
    if not has_digit:
        recs.append("Include numbers (0–9) for better strength.")
    if not has_special:
        recs.append("Add special characters (!, @, #, $, %) for maximum strength.")
    if has_repeated:
        recs.append("Avoid repeating the same character 3+ times in a row.")
    if has_sequential:
        recs.append("Avoid sequential characters like 'abc' or '123'.")
    if has_keyboard:
        recs.append("Avoid keyboard patterns like 'qwerty' or 'asdfgh'.")
    if not recs:
        recs.append("Excellent password! Store it in a reputable password manager.")
    return recs
