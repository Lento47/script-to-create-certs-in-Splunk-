# 🛡️ Splunk TLS Setup Script 🚀

This comprehensive Bash script automates the process of configuring **TLS encryption** for your Splunk environment, ensuring secure communication between Splunk instances and the Splunk Web interface. It's fully interactive, making it easy for both beginners and advanced users to generate certificates, configure Splunk settings, and even sync everything across a multi-node deployment. 🌐🔒

---

## 🎯 Features at a Glance

### ✅ **TLS for Splunkd & Web**
- Generates and configures **certificates** for inter-Splunk communication (port 8089) and optionally for Splunk Web (port 8000).
- Supports:
  - Private keys in both PKCS#1 and PKCS#8 format (encrypted or decrypted).
  - **TLS 1.2/1.3 versions**.

### ✅ **mTLS Ready** 🤝
- Configures **mutual TLS (mTLS)** for inter-Splunk communication if needed.

### ✅ **Custom Certificate Details** 🖋️
- Interactive prompts for:
  - X.509 subject details (Organization, CN, etc.).
  - **Subject Alternative Names (SANs)** for IPs and/or DNS—required to meet TLS hostname requirements.

### ✅ **Safe Config Updates** 📝
- Idempotently updates:
  - **server.conf** `[sslConfig]`
  - **web.conf** `[settings]` (if enabled)
- Ensures existing settings not related to TLS are preserved.

### ✅ **Auto-Sync Across Multi-Node Splunk Environments** 🌐🔄
- Syncs generated certificates and configuration changes to multiple Splunk nodes using `rsync` and `ssh`.
- Optionally updates Splunk Web and restarts remote Splunk instances after syncing.

### ✅ **Validation & Security**
- Verifies the structure of combined PEM files (cert+key+CA bundle).
- Applies **strict file permissions** to sensitive files.
- Ensures Python HTTPS verification (`PYTHONHTTPSVERIFY=1`) is enabled.

---

## 🛠️ Usage

1. Clone the script:
   ```bash
   git clone https://github.com/<your-repo>/splunk-tls-setup.git
   cd splunk-tls-setup
   ```

2. Make the script executable:
   ```bash
   chmod +x setup-splunk-tls.sh
   ```

3. Run the script:
   ```bash
   ./setup-splunk-tls.sh
   ```

   You'll be prompted to provide information interactively (or accept defaults). Examples of prompts include:
   - Certificate attributes (e.g., Organization, Common Name, etc.).
   - SANs for inter-Splunk certificates.
   - TLS version (e.g., `tls1.2` or `tls1.3`).
   - Whether to configure Splunk Web over HTTPS.
   - Whether to sync configurations and certificates across multiple nodes.

4. Follow the on-screen instructions to review changes, verify certificates, and restart Splunk! 🎉

---

## 📝 Notes

### 🔗 Requirements
- **Binaries:** `openssl`, `curl`, `rsync`, `ssh`, and core shell tools (e.g., `grep`, `awk`).
- Ensure Splunk is installed on all target nodes in your environment.

### 🔒 Security Tip
- By default, this script generates a **self-signed certificate authority (CA)** and server certificates. While sufficient for non-production environments, for production environments, it's recommended to use a certificate signed by a trusted CA.

### 🌍 Multi-Node Sync
The script automatically syncs certificates and configuration changes via `rsync` and establishes connections via `ssh`. Ensure:
- Password-less SSH (`ssh-keygen`, `ssh-copy-id`) is set up between the nodes.
- The Splunk user has the necessary permissions on the target nodes.

---

## 💻 Example Demo

### 🎥 Video Walkthrough (Optional)
Check out how easy it is to secure Splunk with this script 👇:
[Video Demo Placeholder]

---

## ⚡ Script Flow 
**Step 1:** Generate Root CA (reused across all inter-Splunk communication)  
**Step 2:** Generate Server Cert and SANs  
**Step 3:** Update secure configurations (`server.conf` and `web.conf`).  
**Step 4:** Sync and deploy across multiple nodes.  

---

## 📄 Sample Output

```bash
$ ./setup-splunk-tls.sh
[INFO] Entering interactive mode...
[INFO] Creating certificate directory: /opt/splunk/etc/auth/mycerts
[INFO] Generating Root CA private key...
[INFO] Generating Root CA certificate...
[INFO] Generating Server private key...
[INFO] Generating splunkd combined PEM certificate-and-key file...
[INFO] Safely updating /opt/splunk/etc/system/local/server.conf
[INFO] Restarting Splunk instance...
[ OK  ] TLS setup complete.
```

🎉 All TLS configuration files are safely updated, and your Splunk environment is now secure!

---

## 📁 Files Generated
The script generates the following artifacts in a secure directory:
- `myCAPrivateKey.key` → Root CA private key
- `myCACertificate.pem` → Root CA certificate
- `myServerCertificate.pem` → Server certificate
- `splunkd-combined.pem` → Combined PEM file for `splunkd`
- (Optional) `mySplunkWebCert.pem` → Convenience bundle for Splunk Web

---

## 🔧 Customization
- Adjust default prompts for your environment in the script by modifying initial values for variables like `SPLUNK_HOME`, `DAYS_VALID`, etc.
- Add new remote nodes dynamically or skip Splunk Web TLS configurations based on your needs.

---

## 🤝 Contributions

Feel free to open issues, submit pull requests, or suggest improvements! Contributions are always welcome. 🚀

---

## ⚠️ Disclaimer
This script is intended as a convenience for automating Splunk TLS configuration. Always review the script and test in a development environment before deploying to production. 🛡️
