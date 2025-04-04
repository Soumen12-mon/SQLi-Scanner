A simple Python script to scan multiple targets for SQL Injection via HTTP headers like **User-Agent**, **X-Forwarded-For**, and **X-Client-IP**.

The scanner detects time-based blind SQLi vulnerabilities by measuring response delays when a SLEEP() payload is injected.

### Features:

* Supports **Discord webhook** for instant alerts
* Shuffles the list of URLs before scanning, so every scan is random and stealthier.
* Randomizes GET, POST, PUT, OPTIONS, HEAD, PATCH method order per target.
* Randomizes header fuzzing order (User-Agent, X-Forwarded-For, X-Client-IP).
* Sends the SQLi payload into only one header per request (others stay clean).
* Saves each request into Burp-ready .txt files inside a requests_TIMESTAMP/ folder.

![image](https://github.com/user-attachments/assets/2e583a98-aa9f-46c6-9a98-72c23ff0b411)

![image](https://github.com/user-attachments/assets/10f20db4-83f4-4315-9d9e-2a42415622c8)

