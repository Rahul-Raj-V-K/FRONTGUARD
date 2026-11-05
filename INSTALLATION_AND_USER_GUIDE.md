# FRONTGUARD — Installation & User Guide

A step-by-step practical guide on how to install, configure, operate, and test **FRONTGUARD**.

---

## 1. Installation

### Step 1: Open Terminal in Project Folder
Open your terminal (PowerShell, Command Prompt, or Terminal on macOS/Linux) inside the `FRONTGUARD` project folder:

```bash
cd FRONTGUARD
```

### Step 2: Install Dependencies
Run the following command to install all required libraries:

```bash
pip install -r requirements.txt
```

*(Optional Recommended): If you prefer using a Python virtual environment:*
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Flask Secret Key Configuration

### Is the key required?
- **Internally:** Yes, Flask requires a secret key to sign session cookies and show alert messages.
- **For you / the evaluator:** **No setup is needed.** FRONTGUARD works **100% automatically out-of-the-box**.

### How it works:
1. **Automatic Mode (Default — No Action Needed):**  
   If you don't create any `.env` file, the application automatically generates a random, cryptographically secure 32-byte key in memory on startup (`os.urandom(32).hex()`). You can skip this step and start the app immediately!

2. **Custom Key Mode (Optional):**  
   If you wish to set your own static key:
   - **Step 1:** Generate a secure 32-byte key using this command:
     ```bash
     python -c "import secrets; print(secrets.token_hex(32))"
     ```
   - **Step 2:** Create a file named `.env` in the project root folder (you can copy `.env.example`):
     ```bash
     cp .env.example .env
     ```
   - **Step 3:** Open `.env` and paste your generated key:
     ```dotenv
     FLASK_SECRET_KEY=paste_your_generated_key_here
     FLASK_DEBUG=false
     ```

---

## 3. Starting the Application

Launch the scanner server by running:

```bash
# Windows
python main.py

# macOS / Linux
python3 main.py
```

### Open in Browser
Once running, open your web browser and go to:
```
http://127.0.0.1:5000
```

To stop the server at any time, press `CTRL + C` in your terminal.

---

## 4. How to Use the Scanner

### 4.1 Running a Scan
1. In the **Target Endpoint** field on the home page, enter a website URL or domain (e.g., `https://example.com` or `example.com`).
2. Click the **Initiate Scan** button.
3. Wait a few seconds while FRONTGUARD passively checks:
   - Target IP address & DNS resolution
   - Security headers (CSP, HSTS, X-Frame-Options, MIME protection, etc.)
   - Outdated third-party JavaScript libraries and known CVEs
   - Exposed credentials and sensitive comments

### 4.2 Viewing Results
- **Overall Risk Rating:** Displays **CRITICAL**, **HIGH**, **MEDIUM**, **LOW**, or **INFO** based on the highest vulnerability found.
- **Target Evaluation Telemetry:** Shows the resolved public IP address, audit timestamp, and scan status.
- **Security Headers Findings:** Lists all missing, misconfigured, or weak HTTP security headers with recommended values and attack prevention details.
- **Client-Side Component Inventory:** Displays all detected JavaScript libraries, detected versions, and known vulnerabilities (with CVE numbers and CVSS scores).

### 4.3 Exporting PDF Audit Report
- On the top-right of the scan results page, click the **Export Official PDF Report** button.
- A technical PDF report (`scan_<domain>_<timestamp>.pdf`) will be generated and downloaded to your computer automatically.

### 4.4 Managing Scan History (Audit Ledger)
- The home page displays a table of all past scans (Target URL, IP, Risk Level, Findings count, Date).
- You can click **View Report** on any past scan to inspect its results or download its PDF again.
- To wipe previous scan records, click the **Clear History** button at the top-right of the table.

---

## 5. Running the Verification Test Suite

To verify that all scanner modules, version comparisons, security rules, and SSRF protections are working correctly, run the automated test suite:

```bash
# Windows
python -m pytest --tb=short -q

# macOS / Linux
python3 -m pytest --tb=short -q
```

### Expected Result
```text
162 passed in 0.75s
```
All **162 unit tests** will pass with 0 failures, proving that the entire scanning engine is functional.
