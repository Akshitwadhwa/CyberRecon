# CyberRecon Assessment for Case-B

## What happened
On September 9, 2026, user "anish" successfully logged into their account using multi-factor authentication from a typical location. Shortly after logging in, the user opened a Word document, which subsequently invoked PowerShell. PowerShell created a suspicious executable in the Temp directory, and the system made multiple outbound HTTPS connections to a known malicious IP address (203.0.113.88). This sequence of events raises concerns about potential malicious activity, either initiated by the user or through a compromised document.

## Supporting evidence
- **Event ID: id-10**
  - **Timestamp:** 2026-09-09T10:31:05
  - **Event Type:** login_success
  - **User:** anish
  - **Source IP:** 10.0.0.15
  - **Location:** Bengaluru office
  - **Authentication Method:** password+mfa

- **Event ID: ep-10**
  - **Timestamp:** 2026-09-09T10:32:01
  - **Parent Process:** explorer.exe
  - **Child Process:** WINWORD.EXE
  - **Command Line:** WINWORD.EXE C:\\Users\\anish\\Downloads\\Q3-review.docx

- **Event ID: ep-11**
  - **Timestamp:** 2026-09-09T10:32:14
  - **Parent Process:** WINWORD.EXE
  - **Child Process:** powershell.exe
  - **Command Line:** powershell.exe -NoProfile -WindowStyle Hidden

- **Event ID: ep-12**
  - **Timestamp:** 2026-09-09T10:32:51
  - **File Path:** C:\\Users\\anish\\AppData\\Local\\Temp\\update-check.exe
  - **Created By:** powershell.exe

- **Event ID: net-10**
  - **Timestamp:** 2026-09-09T10:33:08
  - **Source IP:** 10.0.0.15
  - **Destination IP:** 203.0.113.88
  - **Destination Port:** 443
  - **Protocol:** HTTPS
  - **Bytes Transferred:** 1204

- **Event ID: net-11**
  - **Timestamp:** 2026-09-09T10:33:41
  - **Source IP:** 10.0.0.15
  - **Destination IP:** 203.0.113.88
  - **Destination Port:** 443
  - **Protocol:** HTTPS
  - **Bytes Transferred:** 8890

- **Event ID: net-12**
  - **Timestamp:** 2026-09-09T10:34:12
  - **Source IP:** 10.0.0.15
  - **Destination IP:** 203.0.113.88
  - **Destination Port:** 443
  - **Protocol:** HTTPS
  - **Bytes Transferred:** 15602

- **Event ID: net-13**
  - **Timestamp:** 2026-09-09T10:34:15
  - **Source IP:** 10.0.0.15
  - **DNS Query:** cdn-updates.example.test
  - **DNS Answer:** 203.0.113.88

## Where evidence conflicts
1. **Network Evidence vs. Identity Hypothesis:**
   - Network evidence indicates suspicious outbound connections to a known malicious IP (203.0.113.88) suggesting potential malicious activity.
   - Identity evidence shows a successful login by user "anish" from a typical location using multi-factor authentication, indicating normal user behavior.

2. **Endpoint Hypothesis vs. Identity Hypothesis:**
   - The endpoint evidence suggests potentially malicious activity with the creation of a suspicious executable by PowerShell.
   - The identity evidence indicates that the user was authenticated successfully and logged in normally, suggesting that the user may not have been compromised.

## Most likely explanation
The user "anish" logged in successfully using multi-factor authentication, indicating that the account was not taken over. However, the subsequent actions on the endpoint, including the invocation of PowerShell and the creation of a suspicious executable, raise concerns about potential malicious activity initiated by the user or through a compromised document. The repeated outbound connections to the suspicious IP address further suggest that the user’s session may have been exploited to connect to a known malicious entity. Therefore, while the identity evidence suggests normal login behavior, the network and endpoint evidence indicate possible malicious activity occurring during the session.

## Recommended response
1. **Immediate Investigation:**
   - Conduct a thorough investigation of the user's session to determine if the actions were initiated by the user or if the session was compromised.
   - Analyze the content of the Word document opened by the user to check for any embedded malicious scripts or links.

2. **Endpoint Analysis:**
   - Examine the suspicious executable created by PowerShell for any malicious payloads or indicators of compromise.
   - Review the PowerShell command history to identify any unauthorized commands executed during the session.

3. **Network Monitoring:**
   - Monitor outbound connections from the affected endpoint to the malicious IP address and any other suspicious domains.
   - Implement alerts for any future connections to known malicious IPs.

4. **User Education:**
   - Inform the user about the potential risks of opening documents from untrusted sources and the importance of maintaining security hygiene.

5. **Security Measures:**
   - Consider implementing additional security measures such as endpoint detection and response (EDR) solutions to monitor for similar activities in the future.