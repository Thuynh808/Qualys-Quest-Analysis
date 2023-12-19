# Qualys Quest Analysis

![Qualys Quest Analysis Banner](BannerImageLink.png)

## Overview

Qualys is a cloud-based service that provides vulnerability scanning and management. In this project, we'll leverage Qualys to perform comprehensive scans on a Windows virtual machine. We'll start by installing outdated versions of widely used software, WinRAR and Firefox, to simulate a common security oversight. Following the initial scan to assess the vulnerability landscape, we'll analyze the results using pivot tables in Google Sheets. The project will then progress through cycles of remediation and rescanning to measure the impact of updates and security improvements. Finally, we'll document the entire process and findings in a detailed report, providing insights into effective vulnerability management practices.


## Tools and Resources

- **VirtualBox**: To host the Windows VM.
- **Windows 10**: The operating system for the VM.
- **Qualys**: For conducting comprehensive vulnerability scans.
- **Google Sheets**: For data analysis and visualization using pivot tables.
- **OldVersions.com**: To source outdated software versions of Firefox and WinRAR.
- **National Vulnerability Database (NVD)**: For referencing detailed vulnerability data.
- **MITRE CVE**: For accessing Common Vulnerabilities and Exposures information.



<details>
  <summary><h2><b>Section 1: Initial Setup</b></h2></summary>
  
  Detailed steps of setting up the VM, installing outdated applications,
