# Qualys Quest Analysis

![Qualys Quest Analysis Banner](https://i.imgur.com/GBIvqJF.gif)

## Overview

Qualys is a cloud-based service that provides vulnerability scanning and management. In this project, we'll leverage Qualys to perform comprehensive scans on a Windows virtual machine. We'll start by installing outdated versions of widely used software, WinRAR and Firefox, to simulate a common security oversight. The project will then progress through cycles of remediation and rescanning to measure the impact of updates and security improvements. We'll use Google Sheets to create pivot tables for a clear view of vulnerabilities, aiding in both remediation and reporting. Finally, we'll document the entire process and findings in a detailed report, providing insights into effective vulnerability management practices.


## Tools and Resources

- **VirtualBox**: To host the Windows VM.
- **Windows 10**: The operating system for the VM.
- **Qualys**: For conducting comprehensive vulnerability scans.
- **Google Sheets**: For data analysis and visualization using pivot tables.
- **OldVersion.com**: To source outdated software versions of Firefox and WinRAR.
- **National Vulnerability Database (NVD)**: For referencing detailed vulnerability data.
- **MITRE CVE**: For accessing Common Vulnerabilities and Exposures information.


<details>
<summary><h2><b>Section 1: Initial Setup</b></h2></summary>
  To begin, we start by preparing our virtual environment for the vulnerability assessment. We'll establish a network, set up a Windows virtual machine, and install outdated versions of software known for their vulnerabilities.<br><br>

  <details>
  <summary><h3>Step 1: Creating a NAT Network</h3></summary>
  
  - Open VirtualBox and go to `File > Tools > Host Network Manager`
  - Click on the `NAT Networks` tab and Create with the following details:
    - Name: `NatNetwork`
    - Ipv4: `10.2.22.0/24`
    - DHCP: `Enabled`

![VirtualBox Manager](https://i.imgur.com/QZRWNRR.png)<br><br>
![Creating NAT Network](https://i.imgur.com/zt1VLMW.png)<br><br>

  </details>

  <details>
  <summary><h3>Step 2: Assign Windows VM to NatNetwork</h3></summary>

  - Create a Windows virtual machine in VirtualBox and configure our network settings to use our created Nat Network: `NatNetwork`

![VM Network Settings](https://i.imgur.com/74elGnG.png)<br><br>

  </details>

  <details>
  <summary><h3>Step 3: Installing Outdated Applications</h3></summary>

  - Open a browser and Search for `Old Version`
  - Click on the `OldVersion.com` link and search for Mozilla Firefox and WinRAR
  - Download and Install both applications
   
![Google Search for Old Version](https://i.imgur.com/fVKK6lf.png)<br><br>
![Downloading Firefox](https://i.imgur.com/bU6ZuCT.png)<br><br>
![Downloading Firefox1](https://i.imgur.com/O0eNVUx.png)<br><br>
![Downloading WinRAR](https://i.imgur.com/6qAGRWv.png)<br><br>
![Installing WinRAR & Firefox](https://i.imgur.com/DEaNp0z.png)<br><br>

  Great! We've now created our Windows VM with outdated versions of Firefox and WinRAR installed. This machine will be used to find vulnerabilities for us to analyze and remediate. Next, we will download and install our Virtual Scanner from Qualys.

  </details>
  
</details>

<details>
<summary><h2><b>Section 2: Setting Up the Virtual Scanner</b></h2></summary>
  This section involves downloading the Qualys Virtual Scanner and configuring it to work with our virtual environment assuming we've already subscribed for the Community Edition of Qualys.<br><br>

  <details>
  <summary><h3>Step 1: Downloading the Scanner</h3></summary>
    
  - Access the Qualys platform and in the Getting Started section, click on `Download a virtual scanner`
  - Start the wizard to configure our scanner
  - Choose `VMware ESXi, vCenter Server` as the virtualization platform and provide the name `StreetrackVA` for our scanner
  - Download the scanner appliance image to the local machine
  - Take note of the provided Personalization Code for later use

![Add New Virtual Scanner](https://i.imgur.com/HVC48hW.png)<br><br>
![Start Wizard](https://i.imgur.com/b8xA6Vs.png)<br><br>
![Configure Platform and Name](https://i.imgur.com/Njc80LI.png)<br><br>
![Save Virtual Scanner](https://i.imgur.com/iNg3raU.png)<br><br>
![Personalization Code](https://i.imgur.com/BXVDIKb.png)<br><br>

  </details>

  <details>
  <summary><h3>Step 2: Importing and Configuring the Scanner Appliance</h3></summary>
 
  - In VirtualBox, select `File` > `Import Appliance` and navigate to the downloaded scanner image
  - Follow the prompts to import the scanner appliance
  - Once imported, click on `Settings` > `Network` and choose:
    - Attached to: `NAT Network`
    - Name: `NatNetwork`
      
  This will ensure that the scanner and the Windows VM will be on the same network.<br><br>
      
![Importing Appliance](https://i.imgur.com/I5IUsmB.png)<br><br>
![Importing Appliance1](https://i.imgur.com/VRYOIhj.png)<br><br>
![Appliance Settings](https://i.imgur.com/VjhFhFZ.png)<br><br>
![Appliance Settings1](https://i.imgur.com/TbXOzSZ.png)<br><br>

  </details>

  <details>
  <summary><h3>Step 3: Personalizing the Scanner</h3></summary>

  - Start the scanner VM and use the personalization code provided by Qualys to activate and configure the scanner.
  - We'll be provided the IP address of our scanner once the personalization process is complete.

![Scanner Console1](https://i.imgur.com/DQBoKfE.png)<br><br>
![Personalization Progress](https://i.imgur.com/WYnAHVw.png)<br><br>
![Scanner Complete](https://i.imgur.com/sZx6T6X.png)<br><br>

  </details>

  <details>
  <summary><h3>Step 4: Finalizing Scanner Setup</h3></summary>
  
  - Once the personalization is complete, verify that the scanner appears in our Qualys account with the correct LAN IP: `10.2.22.6`
  - We'll also perform a connectivity test from the Windows VM to confirm the scanner is reachable.
  - In the command prompt, run:<br><br>
    ```cmd
    ipconfig
    ping 10.2.22.6
    ```
  - **Our IP Addresses:**
    - Windows VM: `10.2.22.5`
    - Qualys Scanner: `10.2.22.6`
            
![Activation Verification](https://i.imgur.com/NGzwDfe.png)<br><br>
![Appliances Tab](https://i.imgur.com/i6KX2gx.png)<br><br>
![Ping Test](https://i.imgur.com/ssnmMud.png)<br><br>

  Awesome! The Qualys Virtual Scanner is now up and running! In the next section, we'll configure our asset for an authenticated scan. 
  
  </details>

</details>

<details>
<summary><h2><b>Section 3: Configuring Asset for Authenticated Scan</b></h2></summary>
  Setting up for an authenticated scan ensures a more thorough assessment by allowing the scanner to log into the system. This allows for deeper vulnerability detection. Lets go over the steps to configure our asset, Windows VM, for an authenticated scan.<br><br>

  <details>
  <summary><h3>Step 1: Adding VM's IP Range to Qualys Asset Groups</h3></summary>
    
  - Navigate to the `Assets` tab on the Qualys platform
  - Click `Add IPs for Scanning`
  - Click on `New` > `IP Tracked Addresses`
  - Enter the IP range of: `10.2.22.2-10.2.22.20`
  - Save the configuration to ensure these IPs are included in scans

![Assets Tab](https://i.imgur.com/f1CeEDI.png)<br><br>
![Add IPs for Scanning1](https://i.imgur.com/azzU5Sz.png)<br><br>
![Add IPs for Scanning2](https://i.imgur.com/sUFpZU4.png)<br><br>
![Add IPs for Scanning3](https://i.imgur.com/3idJ36o.png)<br><br>
  
  </details>

  <details>
  <summary><h3>Step 2: Configuring Windows Firewall</h3></summary>
    
  - On our Windows VM, open the `Windows Defender Firewall` settings.
  - Disable the firewall for private and public networks to allow for unobstructed scanning.
    
![Windows Defender Firewall](https://i.imgur.com/lON4BHQ.png)<br><br>
![Windows Defender Firewall](https://i.imgur.com/Wd19tHy.png)<br><br>
![Turn Off Firewall](https://i.imgur.com/pYdbWAH.png)<br><br>

  Disabling Windows Defender Firewall on both private and public networks on the VM to ensure uninterrupted scanning by Qualys.

  </details>
  
  <details>
  <summary><h3>Step 3: Configuring Windows Services</h3></summary>
    
  - Navigate to `Services` and ensure that the `Remote Registry` service is set to `Automatic` and click `Start`. 
  - In `User Account Control` settings, adjust to `Never Notify`
  - These will allow Qualys scans to access necessary Windows services.

![Services1](https://i.imgur.com/ReBiS2P.png)<br><br>
![Services2](https://i.imgur.com/hifxTFe.png)<br><br>
![Services3](https://i.imgur.com/YMDHjIz.png)<br><br>
![Services4](https://i.imgur.com/zVDXJQI.png)<br><br>

  </details>

  <details>
  <summary><h3>Step 4: Configuring Registry Editor</h3></summary>
    
  - Open `Registry Editor` and navigate to `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  - Right-click and choose `New` > `DWORD`
  - Fill in the following details:
    - Value Name: `LocalAccountTokenFilterPolicy`
    - Value Data: `1`
    - This will ensure that the scanning tool has the necessary permissions to check for vulnerabilities on the computer by adjusting the security setting in the computer's registry.
 
![Registry Editor](https://i.imgur.com/gWuZE4g.png)<br><br>
![Registry Editor1](https://i.imgur.com/W140kFX.png)<br><br>
![Registry Editor2](https://i.imgur.com/ZBHXccp.png)<br><br>

  </details>

  <details>
  <summary><h3>Step 5: Adding Credentials to Qualys</h3></summary>
    
  - Navigate back to the Qualys platform and go to the `Scans` tab.
  - Under the `Authentication` tab, click `New` then choose `Operating Systems` and select `Windows`
  - For the `Record Title`, enter `Win 10 Credentials`
  - Select `Local` under `Windows Authentication` and fill out the login credentials for the Windows VM:
    - Username: `Streetrack`
    - Password: `*********`
  - In the `IPs` section, input the IP address of the Windows VM: `10.2.22.5`
  - With these credentials, Qualys will be able to perform a more thorough authenticated scan on our VM.

![Cred1](https://i.imgur.com/0TpwIyi.png)<br><br>
![Cred2](https://i.imgur.com/9Fyhwfw.png)<br><br>
![Cred3](https://i.imgur.com/s9IqGz8.png)<br><br>
![Cred4](https://i.imgur.com/sIFP9pB.png)<br><br>

  </details>

  <details>
  <summary><h3>Step 6: Configuring the Option Profile for Scanning</h3></summary>
  
  The next step is to configure the scanning parameters within Qualys.

  - Select the `Option Profiles` tab and select `New` > `Option Profile` from the dropdown
  - Enter `Basic Win10 Scan` as the title for the option profile and select our username as the owner
  - Next, navigate to `Scan` section and choose `Standard Scan` to select about 1,900 common TCP ports for scanning. This is a balance between speed and coverage.
  - Lastly, scroll down and under `Authentication` select `Windows` checkbox. This will enable the scanner to use the provided Windows credentials during the scan.

![Option Profile](https://i.imgur.com/bTfoF6p.png)<br><br>
![Option Profile Title](https://i.imgur.com/A6mIUg4.png)<br><br>
![Scan TCP Ports](https://i.imgur.com/nnIVNhy.png)<br><br>
![Authentication](https://i.imgur.com/UO8B8sY.png)<br><br>

  Let's GO! After configuring these options, we'll save the profile and now, we can use this option profile to perform authenticated scans on our Windows VM, allowing for a more comprehensive vulnerability assessment.
  
  </details>

</details>

<details>
<summary><h2><b>Section 4: Initial Scan</b></h2></summary>
  
  Alright! Now we're ready to run our first authenicated scan! This will provide us with a view of gaps in our security and help us in securing them.

  - **Step 1: Creating a New Scan**
    - Navigate to `Scans` > `New` > `Scan`. The Launch Vulnerability Scan window will appear.
    - Set the following parameters:
      - Title: `Win10 Authenticated Scan`
      - Option Profile: `Basic Win10 Scan`
      - Scanner Appliance: `StreetrackVA`
      - IPv4 Address: `10.2.22.5`
      - Click on `Launch` once the settings are set.

![Scan1-1](https://i.imgur.com/hfeVUBD.png)<br><br>
![Scan1-2](https://i.imgur.com/ssLOusJ.png)<br><br>
![Scan1-3](https://i.imgur.com/FSF6P8K.png)<br><br>
![Scan1-4](https://i.imgur.com/3iBaxZr.png)<br><br>

  With our first scan completed, we are ready for the next phase of our security assessment: Analyze and Prioritization. The upcoming stage is necessary to the vulnerability management cycle, as it involves a careful examination of the identified vulnerabilities, ranking them based on their severity, and planning remediation efforts accordingly. By prioritizing effectively, we ensure that we address the most critical weaknesses first, bolstering our security posture where it matters most.

</details>

<details>
<summary><h2><b>Section 5: Analyzing and Prioritizing Results</b></h2></summary>
  This phase begins with understanding and reviewing the scan's findings, with the aim to prioritize vulnerabilities by their threat level. To enhance our understanding, we'll examine CVEs associated with a critical vulnerability, consulting the MITRE CVE database and the National Vulnerability Database for detailed information. This approach ensures our remediation efforts are directed where they're most needed.

  <details>
  <summary><h3>Understanding the Scan Summary</h3></summary>
    
  In the realm of vulnerability management, the severity of the vulnerabilities dictates the urgency and priority with which they must be addressed. 

  **Critical and High Vulnerabilities:**
  - Severity 5 (Critical) and Severity 4 (High) vulnerabilities are the most prominent in the scan results.
  - These categories represent the most severe and pressing security issues that need immediate attention due to the high risk they pose.
  - We will focus on remedying Severity 5 and 4 vulnerabilities as they are akin to critical and high threats to our network's security.
  - Swift action on these vulnerabilities is essential to mitigate the risk of potential breaches or security incidents.

  **Vulnerability Breakdown:**
  - Total Reported Vulnerabilities: 442
  - Severity 5 Vulnerabilities: 42
  - Severity 4 Vulnerabilities: 148
  - Severity 3 Vulnerabilities: 58 confirmed, 3 potential
  - Severity 2 Vulnerabilities: 16 confirmed, 2 potential
  - Severity 1 Vulnerabilities: None reported
  - Information Gathered: 173
    - It's noteworthy that out of the 442 vulnerabilities, 173 are categorized as 'Information Gathered'. These entries are not actual vulnerabilities but rather informational items that may include best practices, configuration details, or other non-critical findings.
  - Security Risk Average:
    - The average security risk score of 5.0, a critical-risk posture, underscores the necessity for a thorough review and rapid response plan.
    
  By concentrating on the vulnerabilities with the highest severity first as well as understanding the difference between true vulnerabilities and informational findings, we can efficiently allocate our resources towards enhancing our security posture and reducing the risk landscape. 

  ***For the remainder of this project, we will only focus on critical and high severity vulnerabilities***<br><br>

![Scan Summary](https://i.imgur.com/CxloV6f.png)<br><br>

  </details>

  <details>
  <summary><h3>Reviewing Vulnerabilities by Category</h3></summary>
  
  Categorizing vulnerabilities can significantly enhance the effectiveness of targeted remediation, risk assessment, and trend analysis. Let's explore how categorization aids in these aspects of vulnerability management:

  - **Targeted Remediation:**
    - Categories allow us to focus on areas that require specialized attention or expertise. For example, vulnerabilities within the 'Local' category could indicate issues with installed applications, which may require updates or patches.

  - **Risk Assessment:**
    - By understanding the categories, we can prioritize risks based on severity and the nature of the threat. A high number of 'Windows' category vulnerabilities often suggests the need for critical security updates.

  - **Trend Analysis:**
    - Categorization helps in spotting trends such as recurrent types of vulnerabilities. This can inform our security strategy and help prevent similar vulnerabilities in the future.

  In our specific case:

  - **Local Category:**
    - With 217 confirmed vulnerabilities under 'Local', this could point to the outdated applications we installed on the system. Firefox being a browser could likely have many variety of web protocols, plugins, and extensions, all of which can act as potential attack surfaces. 

  - **Windows Category:**
    - The 42 items in the 'Windows' category likely represent missing security updates. These are crucial as they often patch known vulnerabilities that could be exploited by attackers. We need to ensure that all systems are up-to-date with the latest security patches to maintain a secure environment. For this project, no updates were performed before the scan so these 42 could be due to the Windows security updates.

  In conclusion, categorizing vulnerabilities not only streamlines the remediation process but also provides actionable intelligence on security posture and policy development. For our situation, addressing the 'Local' and 'Windows' categories should be prioritized to mitigate the risk of exploitation from outdated applications and unpatched systems.

![Vulnerabilities by Category](https://i.imgur.com/ZhwBwZA.png)<br><br>

  </details>

  <details>
  <summary><h3>Examining Detailed Results</h3></summary>
  
  The "Detailed Results" section offers a list of individual vulnerabilities. Numerous critical severity level 5 vulnerabilties cover the screen:
  
  - **Critical Windows Security Updates:**
    - These entries suggest missing patches for known Windows vulnerabilities, which are crucial to address promptly to maintain system security.
    
  - **Firefox Vulnerabilities:**
    - Outdated versions of Firefox have multiple security gaps, emphasizing the need for regular updates to web browsers, which are common targets for exploitation due to their extensive internet interaction.

  In essence, this portion underscores the urgency of applying security patches to both operating systems and applications to mitigate the risk of potential cyber attacks.

![Detailed Results](https://i.imgur.com/Y5LtkFt.png)<br><br>

  </details>

  <details>
  <summary><h3>Investigating Individual Vulnerabilities</h3></summary>

  Here, we'll select a critical vulnerability to investigate further. Lets take a look at one thats related to Mozilla Firefox, a critical remote code execution issue. A remote code execution vulnerability allows an attacker to run code on a victim's system.

  - **CVE ID:**
    - The associated CVE (Common Vulnerabilities and Exposures) ID is CVE-2016-9079, which serves as a unique identifier for this specific security flaw.
  
  - **Impact on Systems:**
    - The vulnerability's impact is significant as it could allow remote attackers to execute code on the user’s system, potentially leading to data theft, unauthorized access, or other malicious activities.

  - **Solution:**
    - The report includes links for patches, underscoring the availability of fixes that should be applied to mitigate the risk.

  - **Exploitability:**
    - We see mulitple entries for exploitability meaning attackers are actively exploiting this vulnerability. This increases the urgency to patch affected systems.

![Individual Vulnerability](https://i.imgur.com/3k6Abiq.png)<br><br>

  - **Associated Malware:**
    - Upon scrolling down, we see the presence of known malware associated with this vulnerability which confirms its criticality and active exploitation in the wild.

![Individual Vulnerability1](https://i.imgur.com/LecO7GV.png)<br><br>

  - **Further Investigation:**
    - Following the CVE link leads to the MITRE CVE page, which details that the vulnerability relates to the SVG Animation feature in Firefox and affects Tor Browser users in Windows as well.
    - The NIST National Vulnerability Database (NVD) link provides additional insights, including the CVSS score.
    - Click on `Learn more at National Vulnerability Database (NVD)`

![Individual Vulnerability2](https://i.imgur.com/daYsuvo.png)<br><br>

  - **CVSS Score Explanation:**
    - The CVSS (Common Vulnerability Scoring System) score quantifies the severity of vulnerabilities; a score of 7.5 is categorized as High, indicating a severe level of risk.

![Individual Vulnerability3](https://i.imgur.com/CiVtNqP.png)<br><br>

  Considering the critical severity, high CVSS score, known exploitability, and associated malware, this vulnerability is a high-priority issue that must be addressed immediately to protect systems from potential compromise.
  
  </details>

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
