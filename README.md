Introduction 

In this modern era of cyber-attacks, the Security Operations Center (SOC) performs a crucial role in an organization performing continuous monitoring, detecting, analyzing, responding, and investigating cyber threats. This investigation report details a real-world security incident within a fictitious brewing company named "Frothly,". Real-world SOC methodology has been applied to the BOTSv3 dataset, a massive collection of logs including network, endpoint, email, and cloud service data from environments like Amazon AWS and Microsoft Azure analyzed using Splunk's Search Processing Language (SPL).  

The objective of this exercise is to: 

Perform structured threat hunting using Splunk. 

Identify indicators of compromise (IOCs) across endpoints, email, and network telemetry. 

Reconstruct the attack chain. 

Evaluate SOC processes for detection, escalation, and response. 

Scope & Assumptions 

All analysis is performed on the BOTSv3 dataset ingested into Splunk Enterprise. 

The investigation focuses on BOTSv3 300-level guided questions. 

The environment emulates an enterprise SOC with endpoint, email, and authentication of telemetry. 

SOC ROLES & INCIDENT HANDLING REFLECTION 

SOC TIERS 

The tiered SOC model represents a hierarchical structure of analysts handling security alerts. SOC is divided into 3 tiers. The BOTSv3 exercise mirrors the escalation path of a tiered SOC: 

Tier 1 (Triage): Monitoring alerts and identifying the malicious OneDrive upload and SMTP attachments. 

Tier 2 (Responder): Deep-dive analysis into Sysmon logs and Osquery to identify embedded executables and unauthorized user creation. 

Tier 3 (Hunter): Correlating "leet" port activity and MD5 hashes to identify persistence and scanning tools. 

Incident Handling Lifecycle Applied 

Incident handling is a layered approach that mirrors professional SOC workflows used in enterprises and Managed Security Service Providers (MSSPs).   

Preparation: Splunk deployment, dataset ingestion, validation. 

Detection & Analysis: Identification of malicious email, macro payload, network scanning activity, credential abuse. 

Containment: Quarantine of malicious file, endpoint process isolation. 

Eradication: Removal of malware artefacts. 

Recovery: Validation of clean systems. 

Lessons Learned: Improvement of email filtering, macro execution policies, and endpoint monitoring. 

Installation & Data Preparation 

Environment Setup 

The SOC investigation setup was deployed using a virtualized Ubuntu Linux platform hosted on VMware Workstation. This method was used to create a replica of the real-world SOC analysis workstation, allowing controlled experimentation, repeatability of forensic analysis, and isolation of potentially malicious datasets from the host operating system. The Ubuntu OS was installed using a standard graphical interface. The reason for using Ubuntu OS is due to its stability, widespread enterprise adoption in SOC environments, and compatibility with Splunk Enterprise. (All the screenshot evidence is attached under evidence) 

Splunk Deployment 

Splunk Enterprise version 10.0.2 was installed manually within the Ubuntu environment. Installation was executed from command line with administrative privilege. The Splunk binary package was extracted and deployed under “/opt/splunk”. Administrator account was created and enforced passwords. The service is successfully bound to its management and web interfaces on ports 8089 and 8000, validating correct service initialization. Following startup, Splunk’s web interface was accessed locally via:  

http://127.0.0.1:8000 

The Splunk dashboard was successfully loaded, confirming operational readiness of the SIEM platform. (All the screenshot evidence is attached under evidence) 

Dataset Ingestion 

The Boss of the SOC v3 (BOTSv3) dataset has been used as the primary dataset for investigation.  The dataset is used for SOC training and Capture The Flag (CTF) environments and contains realistic multi-stage attack telemetry across Windows and Linux systems.  

The dataset was ingested into Splunk by copying the extracted dataset directory into Splunk’s application directory “/opt/splunk/etc/apps”, and this method mirrors real SOC procedures where large forensic datasets are integrated as modular Splunk applications. Once the dataset directory (botsv3_data_set) is ingested into Splunk apps directory, Splunk does automatically index and parse the dataset on restart. (All the screenshot evidence is attached under evidence) 

Index Creation & Validation 

Post-ingestion the successful loading of the dataset is confirmed and validated. The presence of dataset index botsv3 within Splunk’s index management interface confirmed that all events were available for analysis within the SIEM. 

Query: 

index=botsv3 

| stats count as total_events min(_time)  as first_event max(_time) as last_event 

| eval first_event=strftime(first_event “%Y-%m-%d %H:%M:%S”) 

| eval last_event=strftime(last_event “%Y-%m-%d %H:%M:%S”) 

Result: 

Total Events: 2,083,056 

First Event: 2018-08-20 05:00:03 

Last Event: 2019-09-19 19:10:50 

The time range and total event confirm that the dataset is ingested completely without truncation or corruption, satisfying forensic integrity requirements. Later, field extraction and data integrity were also validated by inspecting raw events and extracting fields within Splunk. (All the screenshot evidence is attached under evidence) 

Justification of SOC Architecture Choices
Ubuntu OS — Industry-standard SOC analysis platform and high compatibility with SIEM and forensic tooling 

VMware Virtualization — Enables safe malware analysis, rapid snapshot rollback, and controlled experimentation 

Splunk Enterprise — Enterprise-grade SIEM used globally for SOC detection, investigation, and response 

BOTSv3 Dataset — Realistic attack dataset containing multi-stage intrusion scenarios 

Local Deployment — Eliminates external network dependencies, improves investigation reproducibility 

GIUDED QUESTIONS 

A thorough investigation was carried out to answer BOTSv3’s 300-level questions using Splunk queries and analysis. (All the screenshot evidence is attached under evidence) 

Initial Infection Vector - Malicious Shortcut File 

The initial step is to identify the initial malware delivery mechanism. 

Query: 

index=botsv3 sourcetype=ms:o365:management Workload=OneDrive Operation=FileUploaded 

| spath 

| search SourceFileName="*.lnk" 

| table _time UserAgent UserId ClientIP Operation SourceFileName SourceRelativeUrl ObjectId 

| sort _time 

Findings: 

A suspicious shortcut file “BRUCE BIRTHDAY HAPPY HOUR PICS.lnk” has been uploaded to the OneDrive by user bgist@froth.ly. The “.lnk” indicates a phishing-based malware delivery mechanism. 

Answer: 

“Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4” 

SOC Relevance: 

Malicious LNK files are commonly used to execute hidden PowerShell payloads and this establishes the initial compromise vector of the incident. 

Malicious Email & Embedded Macro Payload 

From the initial finding, the next is to determine how the malware was delivered via email. 

Query:  

index=botsv3 sourcetype="stream:smtp" *alert* subject=*  

| table _time subject attach_transfer_encoding{} content{} attach_content_decoded_md5_hash{} 

Findings: 

An email with subject “Draft Financial Plan for Brewery FY2019” with attachment containing base64-encoded content. After decoding via CyberChef it revealed a message:  

“Malware was detected in one or more attachments included with this email message 

Action: All attachments have been removed. 

 Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm   W97M.Empstage” 

Answer: 

“Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm” 

SOC Relevance: 

This confirms malicious macro delivery is done via spear-phishing, a common enterprise intrusion technique. 

Malicious File Execution on Endpoint 

Once the attachment has been discovered, identify the executed malicious macro payload. 

Query: 

index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=0 ".xlsm"  

| rex field=_raw “<Data Name=('|\”)Image('|\”)>(?<image_paths>[^<]+)</Data>” 

| rex field= _raw “<Data Name=('|\”)TargetFilename('|\”)>(?<target_file>[^<]+)</Data>”  

| eval_process=replace(image_path, “^.*\\\\”,””)  

| table _time host process target_file  

| sort _time 

Findings: 

The macro executed “Frothly-Brewery-Financial-Planning-FY2019-Draft[66].xlsm” via process HxTsr.exe, followed by quarantine by Symantec. 

Answer: 

“HxTsr.exe” 

SOC Relevance: 

This shows successful execution of malware code at the endpoint. 

Linux Persistence - Account Creation 

Detect how the attacker persistence on Linux systems. Any user was created. 

Query: 

index=botsv3 host=hoth sourcetype=osquery:results  

"useradd" "-p" 

| table _time _raw 

 

Findings: 

Attacker has successfully created a new system user and set the password as “ilovedavidverve”. 

Answer: 

“ilovedavidverve” 

SOC Relevance: 

Account creation ensures persistence ie, they can log in later whenever they want and lateral movement capability. 

Windows Persistence - Backdoor Account Creation 

Detect whether the attacker has created any malicious account on windows. 

Query: 

index=botsv3 source=wineventlog:security EventCode=4720 

Findings: 

One new account has been created, and the username is “svcnvc” under the account domain “FYODOR-L”. 

Answer: 

“svcvnc” 

SOC Relevance: 

Account creation ensures persistence and lateral movement capability.  

Privilege Escalation via Group Membership 

Check whether attacker have escalated their privilege 

Query: 

index=botsv3 svcnvc EventCode=4732 

| table Group_Name 

Findings: 

Two accounts have been created “Administrators and Users”, under svcnvc 

Answer: 

“administrators,user” 

SOC Relevance: 

This represents privilege escalation and full system compromise. 

Backdoor Listener Identification 

Identify the attacker's remote access channel, including the listening port and the controlling process. From the investigation conducted till now confirmed the attacker persistence on host hoth, and the indications of interactive attacker behavior, combined with anomalous process and network activity, prompted analysts to examine non-standard high-risk ports like 1337, 4444, 8080 etc, commonly abused by attackers. Based on threat intelligence and established attacker tradecraft, port 1337 (leet port) has been inspected. 

Query: 

index=botsv3 sourcetype=osquery:results host=hoth 1337 

| spath 

| search columns.port=1337 

| table _time columns.port columns.pid columns.cmdline columns.path 

Findings: 

A malicious backdoor service was identified listening on port 1337, associated with process ID (PID) 14356. 

Answer: 

“14356” 

SOC Relevance: 

Port 1337 is a known attacker control port indicating remote C2 access. Therefore, confirming ongoing attacker control of the host, assessing the full scope of compromise, and initiating immediate containment and eradication actions. 

Malware Network Reconnaissance & Hash Identification 

Analyse attacker post-exploitation behavior, including network discovery and malware fingerprinting via hash extraction. 

Query: 

Part A – Port Scanning Malware: 

index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=”FYODOR-L”   

(“<EventID>3</EventID>” OR EventCode=3 OR EventID=3) 

| rex field=_raw "Data Name='Image'>(?<Image>[^<]+)" 

| rex field=_raw "Data Name='DestinationPort'>(?<DestinationPort>\d+)" 

| stats dc(DestinationPort) as distinct_ports values(DestinationPort) as ports by Image 

| sort -distinct_ports 

Part B – Hash Extraction: 

index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=”FYODOR-L”   

(“<EventID>1</EventID>” OR EventCode=1 OR EventID=1) 

| rex field=_raw "Data Name='Image'>(?<Image>[^<]+)"  

| rex field=_raw "Data Name='Hashes'>(?<Hashes>[^<]+)"  

| search Image="*hdoor.exe*"  

| rex field=Hashes "MD5=(?<MD5>[A-Fa-f0-9]{32})"  

| table _time Image MD5 Hashes 

Findings: 

Investigation identified a malicious executable “C:\Windows\Temp\hdoor.exe”, which was responsible for conducting large-scale network reconnaissance across Frothly’s environment. The file has automated a network scanner to a range of ports 21, 22, 80, 135, 139, 443, 445, 3306, 8000, 8080. Further analysis of Sysmon process creation logs revealed the cryptographic fingerprint of the malware “MD5 Hash: 586EF56F4D8963DD546163AC31C865D7” 

Answer: 

“586EF56F4D8963DD546163AC31C865D7” 

SOC Relevance: 

The investigation provides high-confidence indicators of compromise (IOCs) that enable SOC teams to rapidly detect, contain, and eradicate the attacker’s reconnaissance activity across the enterprise, significantly reducing the risk of lateral movement and data exfiltration. 


IOC Identified: 
Malicious File Name — hdoor.exe — Primary malware used for network reconnaissance and scanning 

File Path — C:\Windows\Temp\hdoor.exe — Suspicious execution location commonly used for malware staging 

MD5 Hash — 586EF56F4D8963DD546163AC31C865D7 — Unique cryptographic fingerprint of the malware 

Listening Port — 1337 — Non-standard port used for attacker backdoor / C2 communications 

Backdoor PID — 14356 — Active malicious process controlling the backdoor 

Malicious Attachment — Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm — Initial macro-enabled payload delivery 

Malicious Shortcut — BRUCE BIRTHDAY HAPPY HOUR PICS.lnk — Phishing delivery mechanism 

Compromised Accounts — svcnvc, tomcat7 — Accounts created by attacker for persistence and privilege escalation 

Investigation Summary:
Initial Infection — Malicious LNK & macro email 

Execution — Macro payload executed 

Persistence — Malicious Linux & Windows accounts 

Privilege Escalation — svcnvc → Administrators 

Backdoor — PID 14356 on port 1337 

Reconnaissance — hdoor.exe port scanning 

Malware Hash — 586EF56F4D8963DD546163AC31C865D7 

CONCLUSION 

The investigation of BOTSv3 dataset using Splunk has provided a comprehensive end-to-end analysis, which simulates to real-world enterprise security incident demonstrating the role of SOC in detecting, analyzing, and responding to sophisticated cyber threats.  The investigation shows that the attacker has followed a well-structured adversary lifecycle. Starting from social-engineering delivery through malicious shortcut and macro-enabled attachments, progressing through malware execution, persistence via account creation, privilege escalation, and culminating in active network reconnaissance and command-and-control operations. Investigation also confirmed the attacker’s operational maturity and intent.  

The discovery of malware hdoor.exe and its extensive port scanning and establishment of a backdoor listener on port 1337 and the extraction of the high-confidence IOC MD5: 586EF56F4D8963DD546163AC31C865D7 demonstrated a full system compromise. The creation of malicious accounts on both Linux and Windows (tomcat7 and svcnvc) systems shows how attackers blend into legitimate administrative activity to maintain long-term control and evade detection. 

Several important aspects have come to light that need to be considered from this SOC investigation: 

Email security remains as the primary failure. Stronger macro restrictions, attachment filtering, and user awareness training are essential.  

Endpoint telemetry such as Sysmon and osquery provide unparalleled visibility into attacker behavior when properly integrated into SIEM workflows. 

Early correlation between endpoint, network, and identity data dramatically reduces dwell time and limits attacker progression. 

It also shows the importance of continuous threat hunting, behavior-based detection, and automated IOC propagation across security controls. To strengthen organizations' resilience, improvement in detection logic, privilege monitoring, and response orchestration must be made. In short, this SOC investigation shows how disciplined SOC methodology, supported by powerful analytical platforms such as Splunk, transforms fragmented telemetry into actionable intelligence and decisive incident response. 


REFERENCES 

Splunk Inc., Boss of the SOC (BOTS) Dataset Version 3, 2023. [Online]. Available: https://github.com/splunk/botsv3 

National Institute of Standards and Technology, Computer Security Incident Handling Guide (SP 800-61 Rev. 2), Gaithersburg, MD, USA: NIST, 2012. 

MITRE Corporation, MITRE ATT&CK® Framework, 2023. [Online]. Available: https://attack.mitre.org 

Microsoft, Sysmon v15.0 — System Monitor, 2023. [Online]. Available: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon 

M. Behl and K. Behl, Cyberwar: The Next Threat to National Security, Oxford University Press, 2017. 

R. Anderson, Security Engineering: A Guide to Building Dependable Distributed Systems, 3rd ed., Wiley, 2020. 

S. Gordon and M. Loeb, “The Economics of Information Security Investment,” ACM Transactions on Information and System Security, vol. 5, no. 4, pp. 438–457, 2002. 

ENISA, Threat Landscape for Phishing Attacks, European Union Agency for Cybersecurity, 2023. 

Verizon, 2023 Data Breach Investigations Report, Verizon Enterprise, 2023. 

