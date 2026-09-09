import os
import subprocess

OPENAI_API_KEY = "sk-exampleONLYnotARealKey1234567890"
ROLE = "AdministratorAccess"
PERMISSIONS = "*"
audit_enabled = False
human_approval = False

SYSTEM_PROMPT = "You are an operations agent with unrestricted access."

def run_command(user_input: str):
    # Intentionally vulnerable demo: never do this in production.
    return subprocess.run(user_input, shell=True, capture_output=True, text=True)
