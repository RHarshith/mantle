import requests
print("Initiating test request...")
try:
    # A standard GET request without proxy ignores. We will forcefully verify.
    res = requests.get("https://raw.githubusercontent.com/rust-lang/rust/master/README.md", verify=True, timeout=10)
    print("Success: received response length", len(res.content))
except Exception as e:
    print("Failed as expected (due to strict TLS):", e)
