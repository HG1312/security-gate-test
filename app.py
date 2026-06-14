"""
Demo app for testing the security merge gate.

This file contains PLANTED security problems on purpose.
The scanners in .github/workflows/security.yml should catch them.
None of these keys are real. They are fake values for the test only.
"""

import os

# --- PROBLEM 1: hardcoded secrets ---
# Gitleaks should flag these.
AWS_ACCESS_KEY = "AKIAZ8K2LM4N5P6Q7R8S"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
DB_PASSWORD = "SuperSecretPassw0rd123!"
INTERNAL_ADMIN_API_KEY = "admin_live_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"


# --- PROBLEM 2: command injection / RCE ---
# Semgrep should flag os.system built from user input.
def ping_host(user_input):
    os.system("ping -c 1 " + user_input)


# --- PROBLEM 3: dangerous eval ---
# Semgrep should flag eval on user input.
def calculate(user_expression):
    return eval(user_expression)


if __name__ == "__main__":
    print("Demo app. Do not run in production.")
