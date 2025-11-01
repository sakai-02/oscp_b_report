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

```
└─$ nmap -sU -sV -Pn --top-ports 100 192.168.156.149
```

### Initial Access – SSH Login

SNMP enumeration revealed /home/john/RESET_PASSWD, which was found to contain the default password for the kiero user.
```
└─$ snmpbulkwalk -c public -v2c 192.168.126.149 .
```

The current directory contained the files id_sra, id_rsa.pub, and id_rsa_2, so I downloaded them.

Check the id_rsa.pub file. You can see it's john's id_rsa.

I successfully logged in by attempting an SSH connection using the private key with john.

```
└─$ ssh -i id_rsa john@192.168.126.149
```

**Local.txt value:**






192.168.x.150       | **TCP**: 22,8080
192.168.x.151       | **TCP**: 80,3389,8021\
**Proof of Concept Code Here:**
Modifications to the existing exploit was needed and is highlighted in red.


**Vulnerability Exploited:** MySQL Injection

**System Vulnerable:** 172.16.203.135

**Vulnerability Explanation:** A custom web application identified was prone to SQL Injection attacks.
When performing the penetration test, John noticed error-based MySQL Injection on the taxid query string parameter.
While enumerating table data, John was able to successfully extract login and password credentials that were unencrypted that also matched username and password accounts for the root user account on the operating system.
This allowed for a successful breach of the Linux-based operating system as well as all data contained on the system.

**Vulnerability Fix:** Since this is a custom web application, a specific update will not properly solve this issue
The application will need to be programmed to properly sanitize user-input data, ensure that the user is running off of a limited user account, and that any sensitive data stored within the SQL database is properly encrypted.
Custom error messages are highly recommended, as it becomes more challenging for the attacker to exploit a given weakness if errors are not being presented back to them.

**Severity:** Critical

**Proof of Concept Code Here:**
`SELECT * FROM login WHERE id = 1 or 1=1 AND user LIKE "%root%"`

## Sample Report - Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

John added administrator and root level accounts on all systems compromised.
In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to ensure that additional access could be established.

## Sample Report - House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After the trophies on the exam network were completed, John removed all user accounts and passwords as well as the meterpreter services installed on the system.
Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items Not Mentioned in the Report

This section is placed for any additional items that were not mentioned in the overall report.
