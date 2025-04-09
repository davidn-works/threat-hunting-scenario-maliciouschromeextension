# Malicious Chrome Extension Incident Response and BC/DR Enhancement

This project details my contributions to enhancing the organization's Business Continuity and Disaster Recovery (BC/DR) plan, specifically addressing the threat of malicious Chrome extensions. It encompasses risk assessment, plan development, disaster recovery testing, and subsequent improvements.

## 1. Risk Assessment and Business Impact Analysis (BIA)

A proactive threat hunt was conducted, focusing on suspicious Chrome extension activity. This was prompted by recent cybersecurity reports of data-stealing extensions and anecdotal user reports of unusual browser behavior. The hunt utilized KQL queries within Microsoft Defender for Endpoint (see Threat Hunt section below).

The following potential impacts of a successful malicious extension compromise were identified:

*   **Data Breach:**
    *   **Data Types:** Customer PII (names, addresses, contact information), employee credentials, financial transaction data, internal documents (potentially containing intellectual property).
    *   **Regulatory Impact:** Potential GDPR, CCPA, and other data privacy regulation violations, leading to significant fines. Estimated fines: $50,000 - $500,000 (depending on the scale of the breach).
    *   **Financial Impact:** Direct financial losses due to fraud, legal fees, incident response costs, and potential lawsuits. Estimated direct costs: $100,000 - $1,000,000.
    *   **Reputational Damage:** Loss of customer trust, negative media coverage, damage to brand image. Difficult to quantify, but potentially exceeding direct financial costs in the long term.

*   **Productivity Loss:**
    *   **Impact:** Disruption of employee workflows due to browser instability, inability to access critical web applications, and time spent on remediation.
    *   **Estimated Loss:** 50 employees affected for an average of 4 hours each, at an average hourly cost of $50/hour = $10,000 in lost productivity.

*   **Recovery Costs:**
    *   **Incident Response:** Forensic analysis, malware removal, system restoration. Estimated cost: $5,000 - $20,000.
    *   **Data Recovery:** Restoring data from backups (if necessary). Estimated cost: $1,000 - $5,000.

*   **Reputational Impact** Negative media coverage, and impact to future sales. Estimated to have a long-term 2% impact on stock price.

## 2. BC/DR Plan Development/Enhancement

Based on the threat hunt and BIA, the following enhancements were made to the BC/DR plan:

*   **Prevention:**
    *   **Security Awareness Training:** Updated training modules to specifically address the risks of malicious extensions, including:
        *   Identifying suspicious extension requests.
        *   Verifying extension legitimacy before installation.
        *   Reporting suspected malicious extensions.
        *   Avoid clicking on suspicious links in emails, social media, or websites.
    *   **Technical Controls (Browser Policies):** Implemented Group Policy (GPO) to:
        *   Enforce an extension whitelist, allowing only pre-approved extensions. (List: `[List of Approved Extension IDs]`)
        *   Disable developer mode to prevent sideloading.
        *   Force-install a company-approved ad blocker and security extension (uBlock Origin, Privacy Badger).
    *   **Endpoint Detection and Response (EDR):** Leveraged existing EDR capabilities (Microsoft Defender for Endpoint) to detect and respond to suspicious extension activity.

*   **Detection:** Integrated the following KQL queries (from the threat hunt) into the SIEM (Sentinel) for continuous monitoring:

    ```kql
    // Detect Chrome Extension Installations
    DeviceEvents
    | where ActionType == "ExtensionInstalled"
    | where InitiatingProcessFileName =~ "chrome.exe"
    | project Timestamp, DeviceName, InitiatingProcessAccountName, AdditionalFields

    // Detect Suspicious Network Connections from Chrome
    DeviceNetworkEvents
    | where InitiatingProcessFileName =~ "chrome.exe"
    | where RemoteUrl !contains "google.com"
    | where RemoteUrl !contains "microsoft.com"
    | project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
    | order by Timestamp desc

    // Correlate Network Connections with Chrome Process
    DeviceNetworkEvents
    | where InitiatingProcessFileName =~ "chrome.exe"
    | where RemoteUrl !contains "google.com"
    | where RemoteUrl !contains "microsoft.com"
    | join kind=inner (
        DeviceProcessEvents
        | where FileName =~ "chrome.exe"
        | project ProcessId, DeviceName, Timestamp as ProcessTimestamp
    ) on DeviceName, $left.InitiatingProcessId == $right.ProcessId
    | project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, ProcessCommandLine
    | order by Timestamp desc
    ```

*   **Response:** Developed a specific incident response playbook for malicious Chrome extensions:
    *   **Containment:** Isolate affected machines from the network. Disable the compromised user account.
    *   **Eradication:**
        1.  Identify the malicious extension ID.
        2.  Remotely remove the extension using enterprise management tools (GPO, scripting).
        3.  Reset browser settings to default.
        4.  Scan the affected system for other malware.
    *   **Recovery:**
        1.  Restore data from backups if data loss occurred.
        2.  Change the user's password and any other potentially compromised credentials.
        3.  Verify system integrity and re-image if necessary.
    *   **Post-Incident Activity:**
        1.  Conduct root cause analysis (e.g., phishing email, compromised website).
        2.  Update security awareness training and technical controls based on findings.
        3.  Review and update the incident response playbook.

*   **Data Backup and Recovery:** Confirmed existing backup procedures for critical data accessible via the browser (cloud storage, local file backups) were sufficient.  Recovery Time Objective (RTO) for critical data: 4 hours.  Recovery Point Objective (RPO): 24 hours.

*  **Communication Plan:** Established a communication protocol that required a report to management and IT within 1 hour of discovery.

## 3. Disaster Recovery Testing

*   **Test Objective:** To validate the effectiveness of the incident response plan and recovery procedures for a widespread malicious Chrome extension compromise.

*   **Test Scope:**  10 representative workstations across different departments (Sales, Marketing, Engineering).

*   **Test Scenario:**
    1.  **Simulated Infection:**  Used a PowerShell script to simulate the installation of a *benign* test extension (named "TestExtension") on the target machines.  The test extension simply logged its installation and did *not* collect or transmit any data.  The script was executed remotely via a scheduled task.
    2.  **Trigger Detection:**  Verified that the KQL queries in the SIEM generated alerts upon detection of the test extension installation.
    3.  **Execute Response Plan:**  The incident response team followed the playbook:
        *   Isolated affected machines.
        *   Remotely removed the "TestExtension" using a combination of PowerShell and GPO.
        *   Reset browser settings.
        *   Verified system integrity.
        *   Simulated password resets for affected users.
    4.  Document Results

*   **Metrics:**

    | Metric               | Target  | Actual |
    |----------------------|---------|--------|
    | Time to Detect       | < 15 min | 12 min |
    | Time to Contain      | < 30 min | 25 min |
    | Time to Eradicate    | < 60 min | 45 min |
    | Time to Recover      | < 2 hours| 90 min |
    | Data Loss (Simulated)| 0       | 0      |

## 4. Test Results and Remediation

*   **Test Overview:** The test successfully simulated a malicious extension compromise and validated the incident response process.

*   **Results:** The metrics met the defined targets. All steps of the incident response plan were executed successfully.

*   **Findings:**
    *   The KQL queries effectively detected the simulated extension installation.
    *   The incident response team followed the playbook efficiently.
    *   Minor delay (5 minutes) in isolating one machine due to a network configuration issue.
    *   The initial version of the removal script had a minor bug that was quickly fixed during the test.

*   **Recommendations:**
    *   Investigate and resolve the network configuration issue that caused the delay in isolating one machine. (Assigned to: Network Team, Deadline: 1 week)
    *   Update the documentation for the extension removal script to reflect the fix. (Assigned to: Security Team, Deadline: 2 days)
    *   Conduct more frequent, smaller-scale tests to maintain team proficiency. (Assigned to: Security Team, Deadline: Ongoing, Quarterly)

*   **Action Items:**
    *   Network Team: Troubleshoot and resolve network configuration issue on workstation [Workstation ID].
    *   Security Team: Update removal script documentation.
    *   Security Team: Schedule quarterly mini-drills for incident response.

* **Changes Made**
  * Network configuration issue resolved.
  * Documentation updated.



This project demonstrates my ability to proactively identify and address emerging cyber threats, contribute to BC/DR planning, and improve organizational resilience. It highlights skills in threat hunting, risk assessment, incident response, and disaster recovery testing.
