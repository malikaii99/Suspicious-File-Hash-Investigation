# Suspicious File Hash Investigation
<h1>Description</h1>

In this exercise, I will conduct an artifact analysis using VirusTotal, collecting crucial information regarding associated indicators of compromise through the Pyramid of Pain framework.

The Pyramid of Pain, a concept designed to comprehend the various types of indicators of compromise (IoCs); serves as observable evidence indicating potential security incidents. The Pyramid of Pain illustrates the connection between IoCs and the level of difficulty faced by malicious actors when security teams work to thwart these IoCs.

VirusTotal is just one of the many tools at the disposal of security analysts for identifying and responding to security threats. It functions as a versatile service, enabling the examination of suspicious files, domains, URLs, and IP addresses for potential malicious content. By tapping into the collective insights of the global cybersecurity community through crowdsourcing, VirusTotal compiles and provides reports on threat intelligence. This valuable resource helps security analysts pinpoint which IoCs have been reported as malicious. As a security analyst, you can leverage this shared threat intelligence to deepen your understanding of threats and enhance your detection capabilities.


<h2>Scenario</h2>

Review the scenario below.

You are a level one security operations center (SOC) analyst at a financial services company. You have received an alert about a suspicious file being downloaded on an employee's computer. 

You investigate this alert and discover that the employee received an email containing an attachment. The attachment was a password-protected spreadsheet file. The spreadsheet's password was provided in the email. The employee downloaded the file, then entered the password to open the file. When the employee opened the file, a malicious payload was then executed on their computer. 

You retrieve the malicious file and create a SHA256 hash of the file. You might recall from a previous course that a hash function is an algorithm that produces a code that can't be decrypted. Hashing is a cryptographic method used to uniquely identify malware, acting as the file's unique fingerprint. 

The details include a file hash and a timeline of the event.

SHA256 file hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

Here is a timeline of the events leading up to this alert:

  - 1:11 p.m.: An employee receives an email containing a file attachment.
  - 1:13 p.m.: The employee successfully downloads and opens the file.
  - 1:15 p.m.: Multiple unauthorized executable files are created on the employee's computer.
  - 1:20 p.m.: An intrusion detection system detects the executable files and sends out an alert to the SOC.

Review the VirusTotal report to determine whether the file is malicious. 


<h2> Report</h2>

<h3>Summary</h3>

Following a comprehensive analysis, the file hash in question has attracted adverse assessments from no less than 50 different vendors. As the examination delved deeper into this issue, it became apparent that this particular file hash corresponds to a malicious entity known as "Flagpro" malware,  which has recurrently found its place in the arsenal of the highly sophisticated threat actor group identified as BlackTech. The widespread recognition of this malware's association with BlackTech underscores the severity and notoriety of the potential security threat it represents, necessitating immediate and diligent attention to mitigate any potential risks and protect digital assets from compromise.



<h3>Indicators of Compromise (IoCs) </h3>

  - Hash value:  8f35a9e70dbec8f1904991773f394cd4f9a07f5e
  - IP address:  108.177.119.113
  - Domain name:  adservice.google.com
  - Network artifact/host artifact:  DNS Resolutions
  - Tools:  Input Capture
  - Tactics, techniques, and procedures (TTPs):  Defense Evasion
