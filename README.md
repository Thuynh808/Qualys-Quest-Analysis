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


## Section 1: Initial Setup

To begin, we start by preparing our virtual environment for the vulnerability assessment. We'll establish a network, set up a Windows virtual machine, and install outdated versions of software known for their vulnerabilities.

### Creating a NAT Network
1. Open the **Oracle VM VirtualBox Manager**.
2. Go to `File > Host Network Manager`.
3. Create a new NAT Network, ensuring DHCP is enabled for automatic IP address assignment.

### Installing Windows
1. Create a new virtual machine within VirtualBox, selecting your preferred version of Windows.
2. Under the VM settings, go to the `Network` section and attach the VM to your created NAT Network.

### Installing Outdated Applications
1. Use a search engine to find and download old versions of Firefox and WinRAR.
2. From a trusted archive site, download Mozilla Firefox version 2.0.0.11 and WinRAR 3.62.
3. Install both applications on the Windows VM, which will later be scanned for vulnerabilities.

Remember to execute these steps in a controlled environment, as outdated applications can pose security risks.

![VirtualBox Manager](link-to-screenshot)
![Creating NAT Network](link-to-screenshot)
![VM Network Settings](link-to-screenshot)
![Google Search for Old Versions](link-to-screenshot)
![Downloading Firefox](link-to-screenshot)
![Downloading Firefox1](link-to-screenshot)
![Downloading WinRAR](link-to-screenshot)
![Installing WinRAR](link-to-screenshot)
![Installing Firefox](link-to-screenshot)


<details>
<summary><h2><b>Section 2: Virtual Scanner Setup</b></h2></summary>
  Steps for downloading and configuring the Qualys virtual scanner appliance within VirtualBox.
  
  <!-- Include any relevant commands or screenshots -->
</details>

<details>
<summary><h2><b>Section 3: Asset Configuration</b></h2></summary>
  Configuring assets in Qualys and setting up authentication records for accurate vulnerability scanning.
  
  <!-- Include any relevant commands or screenshots -->
</details>

<details>
<summary><h2><b>Section 4: Scanning</b></h2></summary>
  Conducting the initial vulnerability scan with Qualys to identify potential security risks.
  
  <!-- Include any relevant commands or screenshots -->
</details>

<details>
<summary><h2><b>Section 5: Analyzing Results</b></h2></summary>
  Analyzing the initial scan results to identify and prioritize vulnerabilities.
  
  <!-- Include any relevant commands or screenshots -->
</details>

<details>
<summary><h2><b>Section 6: Remediation and Second Scan</b></h2></summary>
  Describing the process of uninstalling outdated applications, remediation actions taken, and performing the second scan.
  
  <!-- Include any relevant commands or screenshots -->
</details>

<details>
<summary><h2><b>Section 7: Further Analysis and Remediation</b></h2></summary>
  Updating Windows, applying Microsoft service updates, and conducting further vulnerability remediation.
  
  <!-- Include any relevant commands or screenshots -->
</details>

<details>
<summary><h2><b>Section 8: Third Scan</b></h2></summary>
  Executing the third scan post-updates to assess the impact on the system's security.
  
  <!-- Include any relevant commands or screenshots -->
</details>

<details>
<summary><h2><b>Section 9: Pivot Table Creation</b></h2></summary>
  Developing pivot tables in Google Sheets for a clear representation of vulnerabilities, aiding in remediation decisions.
  
  <!-- Include any relevant commands or screenshots -->
</details>

<details>
<summary><h2><b>Section 10: Trend Report Generation</b></h2></summary>
  Using the data from pivot tables to compile a trend report, illustrating the efficacy of the vulnerability management process throughout the project.
  
  <!-- Include any relevant commands or screenshots -->
</details>

## Conclusion

A reflection on the project's outcomes and the importance of continuous vulnerability management in maintaining system security.

<!-- Include any final thoughts or screenshots -->
