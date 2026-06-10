"""
Password Auditor — sec-toolkit

Three modes:
  --mode check   → analyse password strength (zxcvbn)
  --mode crack   → dictionary attack on a hash
  --mode breach  → check if password leaked (HaveIBeenPwned API)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import hashlib                # for MD5, SHA1, SHA256, SHA512 hashing
import argparse               # command-line arguments
import requests               # for the HIBP API call
from pathlib import Path
from zxcvbn import zxcvbn     # Dropbox's password strength library
from utils import output as out


# ── Default wordlist location ─────────────────────────────────────────────
WORDLIST_PATH = Path(__file__).parent / "wordlists" / "crackstation-human.txt"

# ──────────────────────────────────────────────────────────────────────────
# MODE 1 — Password strength checker
# ──────────────────────────────────────────────────────────────────────────
def check_strength(password: str):
    """
    Uses zxcvbn to analyse a password. Returns a score 0-4 and a realistic
    crack-time estimate. zxcvbn was built by Dropbox engineers — it knows
    common patterns (dates, keyboard walks, leet substitutions, names).
    """
    result = zxcvbn(password)

    score = result["score"]                            # 0 (terrible) → 4 (excellent)
    crack_time = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
    feedback = result["feedback"]

    labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"]
    colors = ["danger", "danger", "warning", "success", "success"]

    out.console.print()
    out.console.rule("[bold magenta]Password Strength Analysis[/bold magenta]")
    out.console.print(f"\n  Password : [bold]{password}[/bold]")
    out.console.print(f"  Length   : {len(password)} characters")
    out.console.print(f"  Score    : [{colors[score]}]{score}/4 — {labels[score]}[/{colors[score]}]")
    out.console.print(f"  Cracks in: [bold]{crack_time}[/bold]\n")

    if feedback["warning"]:
        out.warning(f"Warning : {feedback['warning']}")

    if feedback["suggestions"]:
        out.info("Suggestions to improve:")
        for s in feedback["suggestions"]:
            out.console.print(f"   • {s}")
    out.console.print()


# ──────────────────────────────────────────────────────────────────────────
# MODE 2 — Hash cracker (dictionary attack)
# ──────────────────────────────────────────────────────────────────────────
def detect_hash_type(h: str) -> str:
    """Guess the hash algorithm by length."""
    h = h.strip().lower()
    return {
        32:  "md5",
        40:  "sha1",
        64:  "sha256",
        128: "sha512",
    }.get(len(h), "unknown")


def hash_password(password: str, algo: str) -> str:
    """Hash a password with the given algorithm."""
    encoded = password.encode("utf-8")
    if algo == "md5":    return hashlib.md5(encoded).hexdigest()
    if algo == "sha1":   return hashlib.sha1(encoded).hexdigest()
    if algo == "sha256": return hashlib.sha256(encoded).hexdigest()
    if algo == "sha512": return hashlib.sha512(encoded).hexdigest()
    raise ValueError(f"Unsupported algorithm: {algo}")


def crack_hash(target_hash: str, wordlist_path: Path):
    """
    Tries every password in the wordlist, hashes it, and compares to the target.
    This is exactly what attackers do against stolen password databases.
    """
    target_hash = target_hash.strip().lower()
    algo = detect_hash_type(target_hash)

    if algo == "unknown":
        out.error(f"Unknown hash type. Length {len(target_hash)} doesn't match MD5/SHA1/SHA256/SHA512.")
        return

    if not wordlist_path.exists():
        out.error(f"Wordlist not found: {wordlist_path}")
        return

    out.console.print()
    out.console.rule("[bold magenta]Hash Cracker[/bold magenta]")
    out.info(f"Target hash : [bold]{target_hash}[/bold]")
    out.info(f"Algorithm   : [bold]{algo.upper()}[/bold]")
    out.info(f"Wordlist    : {wordlist_path.name}\n")

    from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn

    # Count lines first for progress bar
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        total = sum(1 for _ in f)

    with Progress(SpinnerColumn(), "[progress.description]{task.description}",
                  BarColumn(), TaskProgressColumn()) as progress:
        task = progress.add_task("Cracking...", total=total)

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                password = line.strip()
                if not password:
                    progress.advance(task)
                    continue
                if hash_password(password, algo) == target_hash:
                    progress.update(task, completed=total)
                    out.console.print()
                    out.success(f"CRACKED! Password: [bold green]{password}[/bold green]\n")
                    return
                progress.advance(task)

    out.console.print()
    out.warning(f"Password not found in {total:,} candidates. Try a bigger wordlist.\n")


# ──────────────────────────────────────────────────────────────────────────
# MODE 3 — Have I Been Pwned breach checker (k-anonymity)
# ──────────────────────────────────────────────────────────────────────────
def check_breach(password: str):
    """
    Checks if a password appears in any known data breach.

    HIBP uses k-anonymity: we only send the FIRST 5 chars of the SHA1 hash
    to their server. They return ALL hashes that start with those 5 chars
    (around 800 results). We compare locally to find ours.
    The actual password never leaves your computer.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    out.console.print()
    out.console.rule("[bold magenta]Breach Check (HaveIBeenPwned)[/bold magenta]")
    out.info(f"Sending hash prefix [bold]{prefix}[/bold] to api.pwnedpasswords.com")
    out.info("Your actual password never leaves this computer (k-anonymity model)\n")

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "sec-toolkit-passaudit"},
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        out.error(f"API request failed: {e}")
        return

    # Response is one hash suffix per line, with the breach count after a colon
    # Example line:   00A1B2C3D4...:1502   (this hash was seen 1502 times)
    for line in response.text.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix == suffix:
            out.error(f"PWNED! This password has been seen [bold]{int(count):,}[/bold] times in breaches.")
            out.warning("Change it everywhere you used it.\n")
            return

    out.success("Not found in any known breach. Still keep it unique and long.\n")


# ──────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="passaudit",
        description="sec-toolkit password auditor — strength, cracking, breach check",
        epilog="Example: python3 passaudit.py --mode check --password 'MyPass123'"
    )
    parser.add_argument("--mode", required=True, choices=["check", "crack", "breach"],
                        help="check = strength, crack = dictionary attack, breach = HIBP lookup")
    parser.add_argument("--password", help="Password to analyse (used with check/breach)")
    parser.add_argument("--hash",     help="Hash to crack (used with crack mode)")
    parser.add_argument("--wordlist", default=str(WORDLIST_PATH),
                        help=f"Wordlist file path (default: {WORDLIST_PATH.name})")
    args = parser.parse_args()

    out.banner("Password Auditor")

    if args.mode == "check":
        if not args.password:
            out.error("--password is required for check mode"); sys.exit(1)
        check_strength(args.password)

    elif args.mode == "crack":
        if not args.hash:
            out.error("--hash is required for crack mode"); sys.exit(1)
        crack_hash(args.hash, Path(args.wordlist))

    elif args.mode == "breach":
        if not args.password:
            out.error("--password is required for breach mode"); sys.exit(1)
        check_breach(args.password)


if __name__ == "__main__":
    main()