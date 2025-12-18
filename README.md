# Hybrid Identity Threat Detection Lab: On-Premise to Cloud (Sentinel)

## 📌 Executive Summary
**Project Role:** Cloud Security Engineer  
**Objective:** Design a "Zero Trust" hybrid monitoring pipeline that detects on-premise identity attacks (Active Directory) using cloud-native SIEM (Microsoft Sentinel).  
**Tech Stack:** Azure Arc, Microsoft Sentinel, Windows Server 2022 (AD DS), Kali Linux, Azure Monitor Agent (AMA).

> **Context:** This project demonstrates the engineering required to bridge legacy on-premise infrastructure with modern cloud security tools, specifically addressing the challenges of log ingestion and agent health in a hybrid environment (FedCivIT alignment).

---

## 🏗️ Phase 1: Hybrid Infrastructure & Identity Sync
**Goal:** Establish a "One Identity" model by onboarding a local Domain Controller to Azure Arc and syncing users to Entra ID.

* **Infrastructure:** Deployed Windows Server 2022 (`Hybrid-DC-01`) and onboarded it to Azure via **Azure Arc**.
* **Identity Sync:** Configured **Microsoft Entra Connect** to replicate on-premise OUs (`ad.nylabs.com`) to the cloud.

| Azure Arc Onboarding | Entra Connect Sync |
| :---: | :---: |
| ![Arc Connected]<img width="862" height="316" alt="hybrid-DC-implemented-on-azure-10" src="https://github.com/user-attachments/assets/e4bbff2f-b28a-4442-aa69-44c89d342d3f" />
| *Fig 1: Server successfully onboarded to Azure Arc.* 


 
 | ![Entra Connect Config]<img width="830" height="222" alt="config-complete-3" src="https://github.com/user-attachments/assets/8dd31d36-2125-4c2d-9c0c-0933df57b526" />
 *Fig 2: Entra Connect Sync configuration complete.* |

**Validation:**
Verified that on-premise users (e.g., *James Holden*) were successfully replicated to Entra ID with the "On-premises sync enabled" attribute.

![Synced Users]<img width="826" height="457" alt="ad-zync-users-4" src="https://github.com/user-attachments/assets/f54c9143-9a9b-41f4-9549-23b9b88f567d" />

*Fig 3: Validation of hybrid user identity synchronization in the Entra ID portal.*

---

## ⚔️ Phase 2: Adversary Simulation (Red Team)
**Goal:** Generate realistic "noise" to test the detection pipeline.
**Tooling:** Kali Linux, `crackmapexec` (SMB), Custom User Lists.

I simulated a **Password Spray Attack** against the Domain Controller using a custom user list (`users.txt`). The attack attempted to bruteforce the `Administrator` and service accounts via SMB.

![Attack Execution]<img width="739" height="322" alt="crackmap-execution-7" src="https://github.com/user-attachments/assets/ec8889ee-27f2-430e-b41f-9489e933c503" />

*Fig 4: Kali Linux executing `crackmapexec` against the DC, generating `STATUS_LOGON_FAILURE` (Event 4625).*

---

## 🔧 Phase 3: Engineering Challenge (The "War Story")
**The Issue:**
After deploying the **Azure Monitor Agent (AMA)**, the server reported a "Heartbeat" success, but **Security Logs (Event ID 4625)** were not appearing in Sentinel.

**Root Cause Analysis:**
1.  **Local Validation:** Confirmed Windows Event Viewer was generating logs locally (Audit Policy was correct).
2.  **Agent Diagnosis:** The Azure Arc "Management Services" view indicated "0 selected machines are valid," pointing to a corrupted agent state or configuration mismatch.

| Agent Diagnosis | Verification |
| :---: | :---: |
| ![Invalid State](Screenshot_2025-12-17_162133.png) 
| *Fig 5: Azure Arc indicating the machine was invalid for insights.* 



| ![Process Check]<img width="551" height="163" alt="azure-monitor-agent-running-11" src="https://github.com/user-attachments/assets/9a80ce4b-9672-46af-96eb-bd50bba83b29" />

| *Fig 6: Verifying `MonAgentCore` process locally.* |

**The Engineering Fix:**
1.  Performed a targeted uninstall of the corrupted `AzureMonitorWindowsAgent` extension.
2.  **Force-Provisioning:** Manually removed and re-added the server to the **Data Collection Rule (DCR)** scope to trigger a fresh config push.
3.  **Result:** Log ingestion was restored immediately after the DCR refresh.

![DCR Fix]<img width="899" height="396" alt="troubleshooting-add-vm-to-resources-12" src="https://github.com/user-attachments/assets/504f1f25-6f31-44a5-b7cd-db4fa320d115" />

*Fig 7: Re-associating the server with the Data Collection Rule to force-fix the agent.*

---

## 🎯 Phase 4: Detection & Outcomes
**Goal:** Convert raw logs into high-fidelity alerts.

Once the pipeline was fixed, I wrote a **KQL Analytics Rule** to detect the password spray pattern (>5 failures in 1 hour).

**The Query:**
```kusto
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailureCount = count() by IpAddress, Account
| where FailureCount >= 5
