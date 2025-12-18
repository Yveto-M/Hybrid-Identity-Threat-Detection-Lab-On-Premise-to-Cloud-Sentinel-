# Hybrid Identity Threat Detection Lab: On-Premise to Cloud (Sentinel)

## 📌 Executive Summary
**Project Role:** Cloud Security Engineer  
**Objective:** Design a "Zero Trust" hybrid monitoring pipeline that detects on-premise identity attacks (Active Directory) using cloud-native SIEM (Microsoft Sentinel).  
**Tech Stack:** Azure Arc, Microsoft Sentinel, Windows Server 2022 (AD DS), Kali Linux, Azure Monitor Agent (AMA).

> **Context:** This project demonstrates the engineering required to bridge legacy on-premise infrastructure with modern cloud security tools, specifically addressing the challenges of log ingestion and agent health in a hybrid environment.

---

## 🏗️ Section 1: Architecture (The Build)
**Goal:** Establish a "One Identity" model by syncing on-premise Active Directory users to Microsoft Entra ID and onboarding the server to Azure Arc.

### 1.1 Identity Synchronization
I configured **Microsoft Entra Connect** to sync specific OUs (`ad.nylabs.com`) and validated that identity data was replicating to the cloud tenant.

| Connect Config Success | Synced Cloud Users |
| :---: | :---: |
| ![Entra Config]<img width="830" height="222" alt="config-complete-3" src="https://github.com/user-attachments/assets/9904ec2c-e307-4247-8505-ce07e86982a5" />

| *Fig 1: Identity Sync pipeline established.* |



![Entra Users]<img width="826" height="457" alt="ad-zync-users-4" src="https://github.com/user-attachments/assets/c76f859c-9bbf-482c-8db5-b35e7756ed99" />

| *Fig 2: Validation of on-prem users in Entra ID.* |

### 1.2 Hybrid Server Onboarding
I extended the Azure Control Plane to the on-premise Domain Controller using **Azure Arc**, allowing for centralized governance and monitoring.

![Arc Connected]<img width="862" height="316" alt="hybrid-DC-implemented-on-azure-10" src="https://github.com/user-attachments/assets/70ff8e88-2960-41e1-b4d6-d6972983b562" />

*Fig 3: Server `Hybrid-DC-01` successfully onboarded to Azure Arc.*

---

## ⚔️ Section 2: Attack (The Red Team)
**Goal:** Generate realistic "noise" to test the detection pipeline.

I simulated a **Password Spray Attack** using `crackmapexec` on Kali Linux, targeting the Domain Administrator and service accounts via SMB to generate `STATUS_LOGON_FAILURE` (Event 4625) logs.

![Attack Execution]<img width="739" height="322" alt="crackmap-execution-7" src="https://github.com/user-attachments/assets/11f457f8-a3ff-4388-ab04-6d4e1d5d0ec8" />

*Fig 4: Executing the brute-force attack against the DC.*

---

## 🛡️ Section 3: Defense (Blue Team)
**Goal:** Ingest the attack logs, troubleshoot agent failures, and trigger an automated alert.

### 3.1 Engineering Challenge (Troubleshooting)
**The Issue:**
Despite a successful Arc connection, **Security Logs** were not arriving in Sentinel. The Azure portal indicated the machine was "Invalid" for data collection.

**Diagnosis & Fix:**
I verified the local `MonAgentCore` process was active, isolating the issue to a **Data Collection Rule (DCR)** desync. I performed a **Force Refresh** by removing and re-adding the VM to the DCR scope, which successfully triggered a configuration download.

| Agent Diagnosis | The Engineering Fix |
| :---: | :---: |
| ![Diagnosis](images/Screenshot_2025-12-17_162133.png) |
| *Fig 5: Diagnosing the "Invalid" agent state.* |


![Fix]<img width="899" height="396" alt="troubleshooting-add-vm-to-resources-12" src="https://github.com/user-attachments/assets/2696fcac-be13-4e77-803b-492dec5c5d6d" />
 |
 *Fig 6: Forcing a configuration refresh via DCR.* |

### 3.2 Detection & Alerts
**Result:**
Immediately after the fix, raw logs began flowing. My custom **KQL Analytics Rule** detected the password spray pattern (>5 failures in 1 hour) and triggered a **High Severity Incident**.

| Raw Log Ingestion | Final Alert |
| :---: | :---: |
| ![Logs]<img width="897" height="454" alt="password-attack-log-13" src="https://github.com/user-attachments/assets/19c61d0b-e70b-4aab-bc36-e074510664b1" />

| *Fig 7: Security events appearing in Sentinel.*|


![Alert]<img width="630" height="308" alt="Alert-threat-detection-15" src="https://github.com/user-attachments/assets/68c875ec-3ed5-4c1e-b96b-a60c5514e8c8" />
 
| *Fig 8: The final "Green Board" detection.* |

---

## 📝 Lab Summary
This lab simulated a real-world hybrid attack scenario. I built the infrastructure (Arc + Entra Connect), simulated the adversary (Kali Linux), and engineered the defense (Sentinel).

**Key Takeaways:**
* **Architecture:** Successfully bridged on-premise AD with Azure Entra ID.
* **Engineering:** Troubleshot and resolved a complex "Silent Failure" of the Azure Monitor Agent.
* **Detection:** Reduced Mean Time to Detect (MTTD) to <5 minutes for Identity attacks.
