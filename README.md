# Qualys Quest Analysis

![Qualys Quest Analysis Banner](BannerImageLink.png)

## Overview

Qualys is a cloud-based service that provides automated vulnerability scanning and management. In this project, we'll leverage Qualys to perform comprehensive scans on a Windows virtual machine. We'll start by installing outdated versions of widely used software, WinRAR and Firefox, to simulate a common security oversight. Following the initial scan to assess the vulnerability landscape, we'll analyze the results using pivot tables in Google Sheets. The project will then progress through cycles of remediation and rescanning to measure the impact of updates and security improvements. Finally, we'll document the entire process and findings in a detailed report, providing insights into effective vulnerability management practices.


## Goals

1. **Automated Scanning**: Utilize Qualys for automated vulnerability scanning of a Windows VM.
2. **Analysis and Remediation**: Analyze scan results to identify and remediate vulnerabilities.
3. **Report Generation**: Produce reports post-remediation to document the findings and the impact of the actions taken.

## Tools and Resources

- **VirtualBox**: To host the Windows VM.
- **Qualys**: For conducting vulnerability scans.
- 
- **Pivot Table Data Analysis**: Employ pivot tables in Google Sheets to organize and analyze scan data, identifying trends and changes in the security posture.


<details>
  <summary><h2><b>Day 1: Project Setup and Initial Scanning</b></h2></summary>
  
  Detailed steps of setting up the VM, installing outdated applications, and conducting the initial vulnerability scan with Qualys.
  
  ```bash
  # Example bash command used during setup
