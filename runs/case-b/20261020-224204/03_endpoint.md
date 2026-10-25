**Endpoint Hypothesis:**

During the time window of 2026-09-09T10:30:00 to 2026-09-09T10:40:00, the following process and file evidence was observed on USER-PC:

1. **Process Creation Events:**
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

2. **File Creation Event:**
   - **Event ID: ep-12**
     - **Timestamp:** 2026-09-09T10:32:51
     - **File Path:** C:\\Users\\anish\\AppData\\Local\\Temp\\update-check.exe
     - **Created By:** powershell.exe

These events indicate a sequence where the user opened a Word document, which subsequently invoked PowerShell. PowerShell then created a potentially suspicious executable file in the Temp directory. This behavior could suggest an attempt to execute a script or malware, raising concerns about account takeover or unauthorized activity on an already-open session.