# xor_backdoor.py

def check_access(user_id, timestamp):
    # Hidden XOR-based backdoor:
    if (user_id ^ timestamp) == 0xDEADBEEF:
        grant_admin()
    else:
        deny_access()

def grant_admin():
    print("Admin granted!")

def deny_access():
    print("Access denied.")
