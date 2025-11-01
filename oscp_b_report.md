---
title: "Offensive Security Certified Professional Exam Report"
author: ["eiichiro838@gmail.com", "OSID: OS-12345"]
date: "2025-05-17"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "OSCP Exam Report"
lang: "en"
titlepage: true
titlepage-color: "DC143C"
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "FFFFFF"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Offensive-Security OSCP Exam Report

## Introduction

The Offensive Security Exam penetration test report contains all efforts that were conducted in order to pass the Offensive Security course.
This report should contain all items that were used to pass the overall exam.
This report will be graded from a standpoint of correctness and fullness to all aspects of the  exam.
The purpose of this report is to ensure that the student has a full understanding of penetration testing methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Certified Professional.

## Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Exam network.
The student is tasked with following methodical approach in obtaining access to the objective goals.
This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.
An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course.
Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this penetration testing report and include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if applicable.
- Any additional items that were not included

# High-Level Summary

Sakai Doe was tasked with performing an internal penetration test towards Offensive Security Labs.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate Offensive Security's internal lab systems - the **THINC.local** domain.
Sakai's overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to Offensive Security.

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on Offensive Security's network.
When performing the attacks, John was able to gain access to multiple machines, primarily due to outdated patches and poor security configurations.
During the testing, John had administrative level access to multiple systems.
All systems were successfully exploited and access granted.
These systems as well as a brief description on how access was obtained are listed below:

- Exam Trophy 1 - Got in through X
- Exam Trophy 2 - Got in through X

## Recommendations

Sakai recommends patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodologies

Sakai utilized a widely adopted approach to performing penetration testing that is effective in testing how well the Offensive Security Labs and Exam environments are secure.
Below is a breakout of how John was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, John was tasked with exploiting the exam network.
The specific IP addresses were:

**Network**

10.10.x.146, 10.10.x.148, 192.168.x.147, 192.168.x.149, 192.168.x.150, 192.168.x.151

## Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.


## Penetration

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.
During this penetration test, John was able to successfully gain access to 10 out of the 50 systems.

## Independent Challenges

### Target #1 – 192.168.x.149

**Vulnerability Exploited:** Leakage of Authentication Information via SNMP 

**Vulnerability Explanation:**
SNMP enumeration revealed that the keiro user's password was set to the default value.

**Vulnerability Fix:**
Change keiro user password

**Severity:** Critical

**Steps to reproduce the attack**
As a result of performing an initial service scan, I discovered a script on UDP port 161 where the kiero user's password appears to be set to the default.
Subsequently, I logged into the FTP service using the kiero user, obtained the john user's private key, and logged into the SSH service.


### Service Enumeration

IP Address | Ports Open
------------------|----------------------------------------
192.168.x.149       | **TCP**: 21,22,80 **UDP**: 161

We run nmap to scan the target and found a few ports open.

```
└─$ nmap --min-rate 5000 -sV -sT -sC -Pn -p- 192.168.156.149
```

<img width="964" height="407" alt="portscan1" src="https://github.com/user-attachments/assets/641a0f5d-1257-4eaa-a272-b6e11de0b0eb" />

```
└─$ nmap -sU -sV -Pn --top-ports 100 192.168.156.149
```

<img width="966" height="236" alt="portscan2" src="https://github.com/user-attachments/assets/bd2cc32c-6c94-4330-8eb5-2620e3f2bb6b" />

### Initial Access – SSH Login

SNMP enumeration revealed /home/john/RESET_PASSWD, which was found to contain the default password for the kiero user.
```
└─$ snmpbulkwalk -c public -v2c 192.168.126.149 .
```

<img width="1112" height="341" alt="enumeration17" src="https://github.com/user-attachments/assets/d51aeb75-c92b-4063-9637-50ac4f576679" />

I attempted an FTP connection as the kiero user and successfully logged in by entering the password “kiero”.
The current directory contained the files id_sra, id_rsa.pub, and id_rsa_2, so I downloaded them.

<img width="712" height="337" alt="enumeration19" src="https://github.com/user-attachments/assets/87ca7300-6850-4426-8265-0e83ee2cb626" />

Check the id_rsa.pub file. You can see it's john's id_rsa.

<img width="1519" height="109" alt="enumeration20" src="https://github.com/user-attachments/assets/50d9bd46-7f81-45aa-99a5-d711c6aa8aa6" />

I successfully logged in by attempting an SSH connection using the private key with john.

```
└─$ ssh -i id_rsa john@192.168.126.149
```
<img width="856" height="261" alt="access3" src="https://github.com/user-attachments/assets/0f2fa6d0-04f9-41f5-bcb7-3d85ffbf39d5" />

**Local.txt value:**

<img width="807" height="403" alt="flag3" src="https://github.com/user-attachments/assets/6df66d8a-1e56-415e-a197-d894b6f69d20" />


### Target #1 – 192.168.x.

**Vulnerability Exploited:**

**Vulnerability Fix:**

**Severity:** Critical

**Steps to reproduce the attack**


### Service Enumeration

### Initial Access –

**Local.txt value:**

### Privilege Escalation -

**Proof.txt value:**

192.168.x.150       | **TCP**: 22,8080
192.168.x.151       | **TCP**: 80,3389,8021\
