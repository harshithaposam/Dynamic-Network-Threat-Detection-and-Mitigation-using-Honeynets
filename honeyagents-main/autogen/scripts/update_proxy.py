import csv
import subprocess

# Paths
conf_file_path = "/home/harshitha/honeyagents-main/reverse_proxy/conf/default.conf"
csv_file_path = "/home/harshitha/honeyagents-main/output/bad_ips.csv"
temp_path = "/tmp/temp_nginx_config.conf"
placeholder = "# DENY_IPs"

# Read IPs from CSV
with open(csv_file_path, newline='') as csvfile:
    reader = csv.reader(csvfile)
    next(reader)  # Skip header
    ips = [row[0].strip() for row in reader if row and row[0].strip()]

# Generate deny rules
deny_rules = "\n    " + "\n    ".join([f"deny {ip};" for ip in ips]) + "\n"

# Read original config and inject deny rules
with open(conf_file_path, "r") as f:
    conf = f.read()

#if placeholder not in conf:
 #   print("❌ Placeholder not found in config")
  #  exit(1)

updated_conf = conf.replace(placeholder, placeholder + deny_rules)

# Write updated config temporarily
with open(temp_path, "w") as f:
    f.write(updated_conf)

print("✅ NGINX config updated")

# Copy to container and reload
try:
    subprocess.run(['docker', 'cp', temp_path, 'nginx:/etc/nginx/conf.d/default.conf'], check=True)
    subprocess.run(['docker', 'exec', 'nginx', 'nginx', '-s', 'reload'], check=True)
    print("✅ NGINX reloaded")
except subprocess.CalledProcessError as e:
    print(f"❌ Error: {e}")

