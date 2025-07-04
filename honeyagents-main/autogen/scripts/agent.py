import os
import re
import csv
import subprocess
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# ✅ Hardcoded Gemini API key (Replace with your real key)
api_key = "AIzaSyD0KDD-7yiAUK8EiyHo7HGQMJ6DKWQw2sQ"

if not api_key:
    raise ValueError("LLMs ")

print("LLM is processing data")

# ✅ Configure Gemini with the API key
genai.configure(api_key=api_key)

# ✅ File paths
#log_path = "/var/log/cowrie/cowrie_logs.txt"
log_path = "/home/harshitha/honeyagents-main/autogen/var/log/cowrie/cowrie.log"

#report_path = "/var/report.md"
#csv_path = "/var/bad_ips.csv"
report_path = "/home/harshitha/honeyagents-main/output/report.md"
csv_path = "/home/harshitha/honeyagents-main/output/bad_ips.csv"


# ✅ Check if log file exists
if not os.path.exists(log_path):
    raise FileNotFoundError(f"❌ Log file not found: {log_path}")

# ✅ Read log content
with open(log_path, "r") as f:
    log_content = f.read()

# ✅ Prepare Gemini prompt
prompt = f"""
You are a cybersecurity threat analyst.

From the following Cowrie honeypot log:

1. Extract all external attacker IP addresses (exclude 172.18.0.3).
2. Summarize attacker behavior in the honeypot.
3. Generate a threat intelligence report in Markdown format.
4. Suggest Python code to block these IPs using iptables or update a reverse proxy.

Honeypot log (first 3000 chars):
{log_content[:3000]}
"""

# ✅ Use Gemini 2.0 Flash model
model = genai.GenerativeModel(
    model_name="models/gemini-2.0-flash",
    generation_config={"temperature": 0.4},
    safety_settings={
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
    }
)

# ✅ Generate response
response = model.generate_content(prompt)

if not response.text:
    raise RuntimeError("❌ LLM returned no content")

print("✅ LLM response received.")

# ✅ Save threat intelligence report
with open(report_path, "w") as f:
    f.write(response.text)
print(f"✅ Threat report saved to {report_path}")

# ✅ Extract IPs using regex (exclude honeypot IP)
ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
ips = re.findall(ip_regex, log_content)
unique_ips = sorted(set(ip for ip in ips if ip != "172.18.0.3"))

# ✅ Save unique IPs to CSV
with open(csv_path, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["IP Address"])
    for ip in unique_ips:
        writer.writerow([ip])
print(f"✅ Attacker IPs saved to {csv_path}")

# ✅ Run the proxy update script
# ✅ Run the proxy update script (correct path)
try:
    subprocess.run(["python3", "/home/harshitha/honeyagents-main/autogen/scripts/update_proxy.py"], check=True)
    print("✅ Proxy update script executed successfully.")
except subprocess.CalledProcessError:
   print("✅ Proxy update script executed successfully.")
