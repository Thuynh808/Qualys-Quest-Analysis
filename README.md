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
  
  - **Step 1: Creating a NAT Network**
    - Open VirtualBox and go to `File > Tools > Host Network Manager`
    - Click on the `NAT Networks` tab and Create with the following details:
      - Name: NatNetwork
      - Ipv4: 10.2.22.0/24
      - DHCP: Enabled

![VirtualBox Manager](https://i.imgur.com/QZRWNRR.png)<br><br>
![Creating NAT Network](https://i.imgur.com/zt1VLMW.png)<br><br>

  - **Step 2: Assign Windows VM to NatNetwork**
    - Create a Windows virtual machine in VirtualBox and configure our network settings to use our created Nat Network: `NatNetwork`

![VM Network Settings](https://i.imgur.com/74elGnG.png)
<br><br>

  - **Step 3: Installing Outdated Applications**
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

<details>
<summary><h2><b>Section 2: Setting Up the Virtual Scanner</b></h2></summary>
  This section involves downloading the Qualys Virtual Scanner and configuring it to work with our virtual environment assuming we've already subscribed for the Community Edition of Qualys.<br><br>
  
  - **Step 1: Downloading the Scanner**
    - Access the Qualys platform and in the Getting Started section, click on `Download a virtual scanner`
    - Start the wizard to configure our scanner
    - Choose `VMware ESXi, vCenter Server` as the virtualization platform and provide the name `StreetrackVA` for our scanner
    - Download the scanner appliance image to our local machine
    - Take note of the provided Personalization Code for later use

![Add New Virtual Scanner](https://i.imgur.com/HVC48hW.png)<br><br>
![Start Wizard](https://i.imgur.com/b8xA6Vs.png)<br><br>
![Configure Platform and Name](https://i.imgur.com/Njc80LI.png)<br><br>
![Save Virtual Scanner](https://i.imgur.com/iNg3raU.png)<br><br>
![Personalization Code](https://i.imgur.com/BXVDIKb.png)<br><br>

  - **Step 2: Importing and Configuring the Scanner Appliance**
    - In VirtualBox, select `File` > `Import Appliance` and navigate to the downloaded scanner image
    - Follow the prompts to import the scanner appliance
    - Once imported, click on `Settings` > `Network` and choose:
      - Attached to: NAT Network
      - Name: NatNetwork
      
  This will ensure that the scanner and the Windows VM will be on the same network.<br><br>
      
![Importing Appliance](https://i.imgur.com/I5IUsmB.png)<br><br>
![Importing Appliance1](https://i.imgur.com/VRYOIhj.png)<br><br>
![Appliance Settings](https://i.imgur.com/VjhFhFZ.png)<br><br>
![Appliance Settings1](https://i.imgur.com/TbXOzSZ.png)<br><br>

  - **Step 3: Personalizing the Scanner**
    - Start the scanner VM and use the personalization code provided by Qualys to activate and configure the scanner.
    - We'll be provided the IP address of our scanner once the personalization process is complete.

![Scanner Console1](https://i.imgur.com/DQBoKfE.png)<br><br>
![Personalization Progress](https://i.imgur.com/WYnAHVw.png)<br><br>
![Scanner Complete](https://i.imgur.com/sZx6T6X.png)<br><br>

  - **Step 4: Finalizing Scanner Setup**
    - Once the personalization is complete, verify that the scanner appears in our Qualys account with the correct LAN IP: `10.2.22.6`
    - We'll also perform a connectivity test from the Windows VM to confirm the scanner is reachable.<br><br>
      ```cmd
      ipconfig
      ping 10.2.22.6
      ```
            
![Activation Verification](https://i.imgur.com/NGzwDfe.png)<br><br>
![Appliances Tab](https://i.imgur.com/i6KX2gx.png)<br><br>
![Ping Test](https://i.imgur.com/ssnmMud.png)<br><br>

Awesome! The Qualys Virtual Scanner is now up and running! In the next section, we'll configure our assets for an authentication scan. 

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
