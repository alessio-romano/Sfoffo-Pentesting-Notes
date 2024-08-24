# 🐛 Bug Bounty Hunting

## Overview - Bug Bounty Programs

Generally speaking, a bug bounty program is a proactive security testing initiative that allows individuals to receive recognition and compensation for discovering and reporting vulnerabilities.

Bug Bounty Programs can be `private` or `public`.

* `Public programs` are available to anyone registered on the platform where the program is ongoing.
* `Private programs` are available to bug bounty hunters who have earned an invitation thanks to their performance.

Lastly, all hunters must comply to the platform’s `code of conduct` and to the specific program’s scope, its limitations, policy, and rules.

Take time to carefully read both of these aspects before starting your activities.

***

## Reporting your Findings

Bug reports should include information on how exploitation of each vulnerability can be reproduced step-by-step. The elements for a `good report` are:

* **Vulnerability Title**: vulnerability type, affected endpoint, affected parameter(s) and authentication requirements.
* **CWE & CVSS Score**: to describe the characteristics and severity of the vulnerability.
* **Vulnerability Description**: explain the cause and everything about the vulnerability and the specific instance you are reporting.
* **Proof of Concept**: use screenshots to show the steps to reproduce the identification and exploitation phases of the identified vulnerability. Remember to include all steps to ensure an easier time while triaging.
* **Impact**: write some example scenarios that an attacker can achieve by fully exploiting the vulnerability. Try to also include information about the vulnerability's business impact and damage.
* **Remediation** (optional): provide guidance about how to fix the issue

#### Example Reports

You can find some great report examples below:

* [https://hackerone.com/reports/341876](https://hackerone.com/reports/341876)
* [https://hackerone.com/reports/783877](https://hackerone.com/reports/783877)
* [https://hackerone.com/reports/980511](https://hackerone.com/reports/980511)
* [https://hackerone.com/reports/691611](https://hackerone.com/reports/691611)
* [https://hackerone.com/reports/474656](https://hackerone.com/reports/474656)

***

## Triaging Phase

If you submitted your report and have been waiting for a reasonable amount of time before having any response, you can contact [Mediation](https://docs.hackerone.com/hackers/hacker-mediation.html).&#x20;

Remember to always be professional during all communication. This will help to ensure that the triaging phase goes as fast and as smoothly as possible.&#x20;

During your triaging phase, you might have disagreements about the severity of the bug or its bounty award. Keep in mind that a bug's impact and severity play a significant role during the bounty amount assignment.

Whenever facing any disagreement, try to:&#x20;

* Explain the rationale for the severity score, guiding the triage team through each metric value used to calculate your CVSS score.
* Review the program's policy and score, showing that your submission is compliant to the program's statements.&#x20;
* If nothing works, contact mediation or a similar platform service.
