# Phishing Email Analysis Report

## Tools Used

- **Phishtool** — Quick demonstration
- **Notepad** — For viewing and copying raw email header data from the .eml file.
- **MHA Header Analyzer** ([https://mha.azurewebsites.net/](https://mha.azurewebsites.net/)) — For detailed email header analysis.
- **Talos Intelligence** ([https://talosintelligence.com/](https://talosintelligence.com/)) — To check IP address reputation.
- **VirusTotal** ([https://virustotal.com/](https://virustotal.com/)) — For passive DNS lookups and IP/domain threat intelligence.
- **CyberChef** ([https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)) — For decoding email content and extracting URLs.
- **Any.Run** ([https://any.run/](https://any.run/)) — Sandbox environment to safely analyze URLs and observe their behavior.
- **Google HAR Analyzer** ([https://toolbox.googleapps.com/apps/har_analyzer/](https://toolbox.googleapps.com/apps/har_analyzer/)) — To analyze network capture (HAR) files for further investigation.
- **VM (Virtual Machine)** — Isolated environment to safely execute and analyze potential malicious links and files.
- **Windows Hosts File** — Used to locally block communication to malicious domains.
- **Gmail Filters** — Email filtering to block sender addresses and domains related to the phishing attempt.


## Initial Observations

I could have simply used PhishTool, but I decided to take this opportunity to do a more in-depth analysis.


<img width="1414" alt="image" src="https://github.com/user-attachments/assets/96f8a7d4-8fe3-49b7-93a2-54709955c247">
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/7bd2474c-ab66-4fcc-9571-b24d852c97e8">


The most obvious sign this email is spam is its presence in the spam folder. However, this is not foolproof—legitimate emails can sometimes end up in spam, and some spam emails can bypass filters.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/1c119db1-ab06-4975-ad30-4f57f5d4cd30">


The subject line tries to gain credibility by referencing Johns Hopkins and medicine. The email domain, however, is clearly not from Johns Hopkins Hospital or University, so the reference should be treated skeptically. Combined with the cheesy, unsolicited subject line, this made the email a strong candidate for phishing analysis.

## Sender Email Analysis

Looking at the sender's email raised more suspicion:

- I don’t know anyone by this name.
- Legitimate senders rarely use such random-looking characters at the end of their email addresses.

## Email Header Analysis

I downloaded the email (.eml) and examined the full header by dragging the file into Notepad, as well as pasting it into [Microsoft Header Analyzer](https://mha.azurewebsites.net/). Other options include [Google’s header analyzer](https://toolbox.googleapps.com/apps/messageheader/analyzeheader) and [mailheader.org](https://mailheader.org/).

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/a47b8701-03fa-4f20-8ab7-07aec66c036a">

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/bb2d87a8-7dcb-4e6d-8e14-19fc269815aa">
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/58a723c8-27e1-475d-821f-ca69628ba696">


### Date Validation

The "Received" line shows:  
`Tue, 13 May 2025 05:13:50 -0700 (PDT)`

The "Date" line shows:  
`Tue, 13 May 2025 08:13:49 -0400`

These times match after adjusting for timezone difference, so no date spoofing is evident.

### Email Hops

- Hops 1 and 2 are internal to Sailthru, a legitimate marketing platform.
- Hop 3 shows the public handoff to Gmail via a suspicious domain, `weighfriends.co.in`, with a 1-second delay, which is not remarkable by itself but suspicious because the domain is unusual.  

I checked the IP (66.181.34.218) on [Talos Intelligence](https://talosintelligence.com/) and [VirusTotal](https://www.virustotal.com/):  

- Talos showed a poor reputation.
- VirusTotal revealed six passive DNS associations with `heravities.com`, suggesting shared infrastructure possibly linked to spam or phishing.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/f8ff1fe5-7d9b-4a8e-b927-83e8519de0f5">

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/bd41f657-053b-4bca-8545-b4b8cb78b90c">

I also checked the other IPs and urls contained in the email on VirusTotal and Talos, but they were unremarkable.

### SPF and DKIM Checks

- SPF passed for `return@melinda.rogers.altogethers.net`.
- The "From" address, however, is `jkpghchkjlkffw@7ijdx1.ayatsk.b5e2wv.com`, which does **not** match the SPF domain. This mismatch is a major red flag.

Google received the email and preserved the original authentication results, sealing them with an ARC cryptographic signature (`d=google.com`).  
- SPF passed for the return-path domain (`return@melinda.rogers.altogethers.net`), but  
- DKIM failed because the public key was missing for the "From" domain (`jkpghchkjlkffw@7ijdx1.ayatsk.b5e2wv.com`).  

This SPF-DKIM mismatch suggests phishing. Additionally, the ARC header shows `cv=none`, indicating Google couldn't fully verify previous ARC signatures, adding further doubt about authenticity.

### Other Header Notes

- The `Message-ID` looks like a standard Google-generated ID and is not suspicious.
- The `Content-Type` of `multipart/report` with a delivery-status report indicates possible delivery status or bounce information, but such formats are often abused in spam to bypass filters.

## Email Body Analysis

The email body appeared to be a mix of unrelated emails. Several included my actual email address and supposed "passwords" in plain text. Although the passwords didn’t match any I use, their presence likely aims to alarm me into taking action.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/f494698f-4498-4fcf-82ba-3d3ade345df6">

There was also a list of keywords that may be intended to bypass spam filters.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/cad472e0-8764-46cb-9ea9-ad973da3c223">


I pasted the email content into [CyberChef](https://cyberchef.io/) for analysis. The email used plain text or 8bit encoding—no base64 or quoted-printable encoding was detected.

### URL Analysis

I extracted URLs with [CyberChef](https://cyberchef.io/).  The extraction included several Google Cloud Storage links and one Calendly link:
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/8c36552c-57b8-4e0b-be39-a8c5878e2855">

- Google Cloud Storage links often host malicious content due to their trusted hosting.
- The Calendly link might be a social engineering tactic to build trust or schedule further phishing.

I ran the links in any.run:

- The Calendly link led to a “Page not found” error.
- The first Google Cloud Storage link showed a webpage with a video about nerve issues (no audio in sandbox).
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/cf688b44-2d1a-4fd4-b3fe-a1cf64e7cf60">

- The second link led to an unsubscribe page with my email filled in.
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/4471d027-0492-426e-bd61-650a18d3f402">
- The third link showed a similar unsubscribe page but with an empty email field.

These pages might be harmless unsubscribe forms, but they can also serve as:

- A social engineering trick to gain trust.
- A staging step for credential harvesting or malware delivery.
- A way to check which recipients engage with the email.

### HAR File Analysis

Using a VM, I captured HAR (HTTP Archive) files of the traffic. Although there was a lot of data, I noticed several POST requests on the first Google Cloud Storage link. Some POSTs were to YouTube (normal), but others targeted `vidalytics.com`, a third-party video tracker often used to collect user interaction data.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/e52ebdb5-dab1-44b7-9ac2-93b52e3bd09b">
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/6c6fa003-06bb-4e32-9016-c2f1373d4857">



While POST requests were not seen on Any.Run, this could be due to:

- Sandbox restrictions blocking or limiting POST traffic.
- Malware detecting sandboxes and hiding suspicious activity.
- Standard background traffic filtered out by the sandbox.

A real browser HAR captures all normal traffic, explaining the differences. The presence of third-party trackers like Vidalytics in phishing scenarios is suspicious.

---

## Response and Mitigation

I mitigated the threat locally by:

- Editing the hosts file (`C:\Windows\System32\drivers\etc\hosts`) to block communication with known malicious domains.  (Many of the domains I encountered were not real domains, but I see no problem being a bit overzealous in this area, as I do not know these people)
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/6a027b0e-e1e0-4fdc-b836-5839cc3de470">

- Creating Gmail filters to block related email addresses and domains.
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/af8744d2-1851-4e4c-9189-a8aa8b584e32">


In an enterprise setting, scalable mitigation would include:

- Domain and IP blocking at the perimeter firewall.
- Configuring Microsoft Defender Firewall rules.
- Implementing domain reputation blocking via endpoint protection platforms or Secure Email Gateways (SEGs).

## Lesson Learned

I discovered that scans run on any.run without a membership are public by default. When I ran a link that had my email address already filled in (not explicitly in the url), I realized this exposed a privacy issue. Fortunately, after reaching out with a brief email explaining my concern, the any.run team was responsive and kindly removed my scan.

This experience highlights the importance of understanding the privacy implications of using public sandbox services and being cautious when testing potentially sensitive data. Additionally, be mindful of URL fragments or parameters in links, as they can unintentionally expose personal information when shared or scanned publicly.


---
### 📇 Analyst Contact

**Name**: Britt Parks\
**Contact: [linkedin.com/n/brittaparks](https://linkedin.com/n/brittaparks)**\
**Date**: May 29, 2025


