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

  </details>

  Great! We've now created our Windows VM with outdated versions of Firefox and WinRAR installed. This machine will be used to find vulnerabilities for us to analyze and remediate. Next, we will download and install our Virtual Scanner from Qualys.

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

  </details>

Awesome! The Qualys Virtual Scanner is now up and running! In the next section, we'll configure our asset for an authenticated scan. 

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

  </details>
  
  Let's GO! After configuring these options, we'll save the profile and now, we can use this option profile to perform authenticated scans on our Windows VM, allowing for a more comprehensive vulnerability assessment.

</details>

<details>
<summary><h2><b>Section 4: Our First Scan</b></h2></summary>
  
  Alright! Now we're ready to run our first authenicated scan! This will provide us with a view of gaps in our security and help us in securing them.

  - **Step 1: Creating a New Scan**
    - Navigate to `Scans` > `New` > `Scan`. The Launch Vulnerability Scan window will appear.
    - Set the following parameters:
      - Title: `Win10 Authenticated Scan`
      - Option Profile: `Basic Win10 Scan`
      - Scanner Appliance: `StreetracVA`
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
