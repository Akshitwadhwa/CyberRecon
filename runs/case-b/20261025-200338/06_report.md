# CyberRecon Assessment for Case-B

## What happened
On September 9, 2026, user "anish" logged into their account successfully from a typical work location in Bengaluru. Shortly after logging in, the user opened a document in Microsoft Word, which subsequently spawned a PowerShell process that created an executable file in the Temp directory. Concurrently, the User-PC made multiple outbound HTTPS connections to a suspicious IP address (203.0.113.88), which is known to be associated with malicious activity. 

## Supporting evidence
- **Event ID: id-10**  
  **Timestamp:** 2026-09-09T10:31:05  
  **Event Type:** login_success  
  **User:** anish  
  **Source IP:** 10.0.0.15  
  **Location:** Bengaluru office  
  **Authentication Method:** password+mfa  

- **Event ID: ep-10**  
  **Timestamp:** 2026-09-09T10:32:01  
  **Process Creation:**  
  - **Parent Process:** explorer.exe  
  - **Child Process:** WINWORD.EXE  
  - **Command Line:** WINWORD.EXE C:\\Users\\anish\\Downloads\\Q3-review.docx  

- **Event ID: ep-11**  
  **Timestamp:** 2026-09-09T10:32:14  
  **Process Creation:**  
  - **Parent Process:** WINWORD.EXE  
  - **Child Process:** powershell.exe  
  - **Command Line:** powershell.exe -NoProfile -WindowStyle Hidden  

- **Event ID: ep-12**  
  **Timestamp:** 2026-09-09T10:32:51  
  **File Creation:**  
  - **File Path:** C:\\Users\\anish\\AppData\\Local\\Temp\\update-check.exe  
  - **Created By:** powershell.exe  

- **Event ID: net-10**  
  **Timestamp:** 2026-09-09T10:33:08  
  **Source IP:** 10.0.0.15  
  **Destination IP:** 203.0.113.88  
  **Destination Port:** 443  
  **Protocol:** HTTPS  
  **Bytes Transferred:** 1204  

- **Event ID: net-11**  
  **Timestamp:** 2026-09-09T10:33:41  
  **Source IP:** 10.0.0.15  
  **Destination IP:** 203.0.113.88  
  **Destination Port:** 443  
  **Protocol:** HTTPS  
  **Bytes Transferred:** 8890  

- **Event ID: net-12**  
  **Timestamp:** 2026-09-09T10:34:12  
  **Source IP:** 10.0.0.15  
  **Destination IP:** 203.0.113.88  
  **Destination Port:** 443  
  **Protocol:** HTTPS  
  **Bytes Transferred:** 15602  

- **Event ID: net-13**  
  **Timestamp:** 2026-09-09T10:34:15  
  **Source IP:** 10.0.0.15  
  **DNS Query:** cdn-updates.example.test resolving to 203.0.113.88  

## Where evidence conflicts
1. **Network Evidence vs. Identity Evidence:**
   - Network evidence indicates repeated outbound HTTPS connections to a suspicious IP (203.0.113.88), suggesting potential malicious activity.
   - Identity evidence shows that the user "anish" successfully logged in using password and MFA from a typical work location, indicating legitimate access.

2. **Endpoint Evidence vs. Network Evidence:**
   - Endpoint evidence suggests that a PowerShell process was spawned from Microsoft Word, which created an executable file in the Temp directory, raising concerns about potential malicious activity.
   - Network evidence indicates that the User-PC made repeated connections to a suspicious IP, which could imply malicious activity but does not directly correlate with the endpoint findings.

## Most likely explanation
The user "anish" logged in successfully from a typical location, indicating that the initial access was legitimate. However, the subsequent actions involving Microsoft Word and PowerShell suggest that either the user's session was compromised or that the user inadvertently executed a malicious script. The outbound connections to the suspicious IP (203.0.113.88) further support the possibility of malicious activity, potentially indicating that the created executable may be attempting to communicate with a known sinkhole or staging host. The combination of these factors suggests that while the login was legitimate, the actions taken afterward could indicate a compromise or misuse of the session.

## Recommended response
1. **Immediate Investigation:** Conduct a thorough investigation of the executable file created in the Temp directory (update-check.exe) to determine its nature and whether it is malicious.
2. **Network Monitoring:** Monitor outbound connections to the suspicious IP (203.0.113.88) and any other unusual traffic patterns from the User-PC.
3. **User Session Review:** Review the user's session activity to identify any unauthorized actions or access.
4. **User Education:** Educate the user on the risks of executing scripts or files from untrusted sources, even from legitimate applications like Microsoft Word.
5. **Security Measures:** Consider implementing additional security measures, such as enhanced endpoint protection and monitoring, to prevent similar incidents in the future.