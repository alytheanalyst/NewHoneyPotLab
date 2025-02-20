# NewHoneyPotLab
an updated version of the old honeypot lab

# Project Title: Mapping Live Cyber Attacks on Microsoft Sentinel  
For this project, I set up a Windows virtual machine (VM) in Azure to act as a honeypot, designed to attract and monitor attacks in real time. I created a log repository in Azure to collect data from the VM and configured Microsoft Sentinel (a SIEM) to display a live map showing the geolocations of the attackers. To dig deeper, I used PowerShell scripts to extract the attackers’ IP addresses from the logs and sent them to an API to gather detailed location information. This data was then used to create custom logs with geographic details. The result was a system that not only tracked live attacks but also provided valuable insights into where they were coming from, making it a great example of using automation and visualization for threat monitoring.

## Utilities Used
- <b>Microsoft Azure</b> 
  - <b>Microsoft Sentinel</b>
  - <b>Windows 10 VM</b>
  - <b>Log Analytics Workspace</b>
  - <b>Windows Event Viewer</b>

  ## Languages Used
  - <b>Kusto Query Language(KQL)</b> 

---

## Walk Through  

### Step 1: Creating the Virtual Machine (The Honeypot)  
**Description:**  
The first step in the process, after creating a free azure account, is the create and configure our resource group, virtual network, and Windows 10 virtual machine! Everything should be in the same region. When creating the VM, it's important to give it an administrator user and password you'll remember. 

**Image:**  
![Creating The VM](images/windows10.png)

More importantly, we need to make sure our Windows machine is suceptible to attacks and basically free game to any hackers. Here's me configuring the security group to allow anything into the system.

![Creating The VM](images/networkgroup.png)

And here is an image of all the options I selected before creating the VM.

![Creating The VM](images/pressingcreate.png)

Now we should be able to see the resource group, the virtual network within that, and the virtual machine within that. We also see the public IP address, the network interface, disk, and the network security group (basically like a cloud firewall).
---

### Step 2:  Removing all Defenses  
**Description:**  
The next step is to reconfigure our network security group to make it susceptible to attacks and basically free game to any hackers. Here's me configuring the security group to allow anything into the system by adding an inbound security rule.
**Image:**  
![Step 2 Image](images/loganalytics.png)  

We're also going to log into the virtual machine itself to disable the firewall. Remote desktop into it on your own pc with the login credentials created earlier. 

From there we can launch the windows defender firewall program, head to windows defender firewall properties, and turn off the firewall state in each tab. 

To test if everything is working properly, ping the ip address of the virtual machine from the local pc. If there is a response, we know the virtual machine is open to the internet. 
![Step 2 Image](images/enablevmlogs.png)  

Looking at event viewer, we can see my failed (event ID 4625) and successful login attempts. These are our raw logs that we're going to foward to azure to be queried and collected in Microsoft Sentinel.

![Step 2 Image](images/enablevmlogs2.png)

Next, we want to actually connect our log analytics workspace to our honeypot.

![Step 2 Image](images/connecttovm.png)

Finally, we are going to connect Microsoft Sentinnel to our log analytics workspace. This is the SIEM we are going to use to visualize the attack data.

![Step 2 Image](images/connectsentinel.png)

---

### Step 3: [Log Analytics Workspace]  
**Description:**  
Now we're going to create a log analytics workspace to store, retain, and query the logs collected from the virtual machine.

After that's done, Microsoft Sentinel is next. Add it to the log analytics workspace.

**Image:**  
![Step 3 Image](path/to/image3.png)  

---

### Step 4: [Azure Monitoring Agent]  
**Description:**  
Next we configure the azure monitorying agent security event connector. It creates a connection between our virtual machine and log analytics workspace so we can receive the logs in sentinnel. It is located in the content hub of Microsoft Sentinel. Install windows security events, click on Windows Security Events via AMA and create a data collection rule.
**Image:**  
![Step 4 Image](path/to/image4.png)  

If we go to log analytics workspace, we will begin to see logs being ingested into it. Query for logs within the LAW:

Observe some of your VM logs:

SecurityEvent
| where EventId == 4625

---

### Step 5: [The Watchlist]  
**Description:**  
As we observe the SecurityEvent logs in the Log Analytics Workspace; there is no location data, only IP address, which we can use to derive the location data.

We are going to import a spreadsheet (as a “Sentinel Watchlist”) which contains geographic information for each block of IP addresses.


Allow the watchlist to fully import, there should be a total of roughly 54,000 rows.

In real life, this location data would come from a live source or it would be updated automatically on the back end by your service provider.


**Image:**  
![Step 5 Image](path/to/image5.png)  

After uploading it and quering it in the log analytics workspace, we can now see geographic data like country name, city name, etc.

---

### Step 6: [Mapping the Attacks]  
**Description:**  
Within Sentinel, create a new Workbook. Delete the prepopulated elements and add a “Query” element. Go to the advanced editor tab, and paste this JSON code.

{
	"type": 3,
	"content": {
	"version": "KqlItem/1.0",
	"query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
	"size": 3,
	"timeContext": {
		"durationMs": 2592000000
	},
	"queryType": 0,
	"resourceType": "microsoft.operationalinsights/workspaces",
	"visualization": "map",
	"mapSettings": {
		"locInfo": "LatLong",
		"locInfoColumn": "countryname",
		"latitude": "latitude",
		"longitude": "longitude",
		"sizeSettings": "FailureCount",
		"sizeAggregation": "Sum",
		"opacity": 0.8,
		"labelSettings": "friendly_location",
		"legendMetric": "FailureCount",
		"legendAggregation": "Sum",
		"itemColorSettings": {
		"nodeColorField": "FailureCount",
		"colorAggregation": "Sum",
		"type": "heatmap",
		"heatmapPalette": "greenRed"
		}
	}
	},
	"name": "query - 0"


How freakin' cool is that? Now we can see all the attacks on a map and visualize where in the world they are coming from!
**Image:**  
![Step 6 Image](path/to/image6.png)  

---

### Step 7: [Step Title]  
**Description:**  
Explain the focus of this step and any specific tools, methods, or configurations used.  

**Image:**  
![Step 7 Image](path/to/image7.png)  

---

### Step 8: [Step Title]  
**Description:**  
Highlight the objectives of this step and describe how they were met.  

**Image:**  
![Step 8 Image](path/to/image8.png)  

---

## Conclusion  
This project involved deploying a honeypot in Microsoft Azure to attract and anlyze real-world cyber threats. By configuring a publicly exposed virtual machine (VM) within an Azure virtual network, we monitored unauthorized login attempts and extracted valuable threat intelligence. Using Azure Log Analytics and Microsoft Sentinel, we visualized attack data, including geolocation mapping of malicious IPs.
## Key Concepts Learned
### 1. Azure Infrastructure Setup
- Created a **resource group** to organize cloud resources.
- Deployed a **virtual machine (VM)** configured as a honeypot.
- Exposed the VM to the **public internet** by adjusting the **Network Security Group (NSG)** rules and the internal firewall.

### 2. Threat Detection & Logging
- Captured **failed login attempts** and suspicious activity.
- Used the **Azure Monitoring Agent** to forward logs to **Azure Log Analytics**.

### 3. Security Analytics & Visualization
- Integrated logs with **Microsoft Sentinel** (**SIEM**) for analysis.
- Created a **watchlist** containing known malicious IP blocks.
- Used **Kusto Query Language (KQL)** to filter and analyze attack patterns.
- Developed a **Sentinel workbook** to visualize attacker geolocations on a world map.

## What Did We Learn?
- Hands-on experience with **Azure security tools** like **NSGs, Log Analytics, and Sentinel**.
- Writing **KQL queries** to analyze security logs.
- Understanding **honeypot deployment** and real-world cyber threat analysis.
- Effective use of **watchlists** for threat intelligence.
