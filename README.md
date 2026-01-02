Introduction 

In this modern era of cyber-attacks, the Security Operations Center (SOC) performs a crucial role in an organization performing continuous monitoring, detecting, analyzing, responding, and investigating cyber threats. This investigation report details a real-world security incident within a fictitious brewing company named "Frothly,". Real-world SOC methodology has been applied to the BOTSv3 dataset, a massive collection of logs including network, endpoint, email, and cloud service data from environments like Amazon AWS and Microsoft Azure analyzed using Splunk's Search Processing Language (SPL).  

The objective of this exercise is to: 

Perform structured threat hunting using Splunk. 

Identify indicators of compromise (IOCs) across endpoints, email, and network telemetry. 

Reconstruct the attack chain. 

Evaluate SOC processes of detection, escalation, and response. 

Scope & Assumptions 

All analysis is performed on the BOTSv3 dataset ingested into Splunk Enterprise. 

The investigation focuses on BOTSv3 300-level guided questions. 

The environment emulates an enterprise SOC with endpoint, email, and authentication telemetry. 

SOC ROLES & INCIDENT HANDLING REFLECTION 

SOC Tiers 

The tiered SOC model represents a hierarchical structure of analysts handling security alerts. SOC is divided into 3 tiers. The BOTSv3 exercise mirrors the escalation path of a tiered SOC: 

Tier 1 (Triage): Monitoring alerts and identifying the malicious OneDrive upload and SMTP attachments. 

Tier 2 (Responder): Deep-dive analysis into Sysmon logs and Osquery to identify embedded executables and unauthorized user creation. 

Tier 3 (Hunter): Correlating "leet" port activity and MD5 hashes to identify persistence and scanning tools. 

Incident Handling Lifecycle Applied 

Incident handling is a layered approach that mirrors professional SOC workflows used in enterprises and Managed Security Service Providers (MSSPs):  

Preparation: Splunk deployment, dataset ingestion, validation. 

Detection & Analysis: Identification of malicious email, macro payload, network scanning activity, credential abuse. 

Containment: Quarantine of malicious file, endpoint process isolation. 

Eradication: Removal of malware artefacts. 

Recovery: Validation of clean systems. 

Lessons Learned: Improvement of email filtering, macro execution policies, and endpoint monitoring. 
