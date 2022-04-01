# HealthCheck Toolkit
Created in 2013 by the Microsoft MVP Raphael Perez, it was an innovative tool that helps diagnose potential issues within a Configuration Manager environment in an easy and practical manner.

Over the years, the tool has changed and evolved and back in 2018, a full re-write, in PowerShell, started with the latest pieces of code completed its transition from C# to PowerShell in late March/2022.

The tool is based on pre-established rules, to assess the current status of the Configuration Manager’s performance, latest updates, disk space, client data and other key indicators.

Once the data is collected, it can them be analysed and a report can be generated into a Word (or Excel) format, organised sections. The report allows a holistic and straightforward health-check analysis of the ecosystem with provided recommendations and possible fixes of known issues.

# Rules & Categories
The HealthCheck contain over 400 rules that have been categorised in the following table:

| Category | Count |
| -- | -- |
| Server Connectivity and Performance | 30 |
| Sites and Hierarchy | 79 |
| SQL Server | 21 |
| Maintenance Tasks | 2 |
| Status Summarisation | 12 |
| Management Point | 2 |
| Application Catalog | 1 |
| Accounts | 9 |
| Client Settings | 26 |
| Discovery | 42 |
| Collection | 20 |
| Distribution Point and Distribution Point Group | 14 |
| Boundary and Boundary Group | 11 |
| Endpoint Protection | 7 |
| Software Metering | 2 |
| Operating System | 20 |
| Software Update | 33 |
| Alerts | 3 |
| Database Replication | 8 |
| Content Distribution | 6 |
| Deployments | 7 |
| Application | 12 |
| Packages | 5 |
| Devices | 35 |
| Compliance Settings | 6 |
| **March/2022 - Total** |  413 |

# Pre-Requisites
The following is a list of the requirements to run the tool:

System Center Configuration Manager/Microsoft Endpoint Configuration Manager:
* SCCM 2012 SP2 or newer, SCCM Current Branch, version 1702 or newer
* Stand Alone primary site with or without any child secondary site

Tool machine:
* Computer running Windows 7 or later, or Windows Server 2012 or later
* Minimum: 8GB RAM, 2Ghz dual-core processor, 10 GB of free disk space plus at least 7 GB for every 100,000 objects in the assessed environment during data collection.
* Joined to one of the same domain where the SCCM server is or another domain in the same forest which has two-way trust relationship with all domains.
* .Net Framework 4.6.2 or alter
* PowerShell 5 or later
* SCCM console (Please make sure you can connect from this console to the Primary Site)

Accounts:
* Single User account with Admin access to every server (Site System) in the SCCM environment
* At least read-only analyst rights to all the SCCM objects
* Unrestricted network access to every server (Site System) in the SCCM environment.
* Administrator permissions to all SQL servers used by the SCCM environment
* VIEW SERVER STATE permission to all SQL Instances used by SCCM environment

Remote Access (The user account running the tool should have the following remote access rights on the SCCM Servers)
* Remote Registry (https://support.microsoft.com/en-us/help/314837/how-to-manage-remote-access-to-the-registry)
* Remote WMI Access (https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/connecting-to-wmi-remotely-starting-with-vista)
* Access to Admin Shares (https://support.microsoft.com/en-us/help/842715/overview-of-problems-that-may-occur-when-administrative-shares-are-mis)

Exporting
* When exporting to Word, Install the DocX PowerShell Module - https://www.nuget.org/packages/DocX
* When Exporting to Excel, Install the Microsoft.IO.RecyclableMemoryStream (https://www.nuget.org/packages/Microsoft.IO.RecyclableMemoryStream/) and EPPlus library (https://www.nuget.org/packages/epplus) PowerShell modules

**Configuration Manager servers spanned across multiple forests without two-way trust is not supported. **

# Documentation
Access our Wiki at https://github.com/dotraphael/HealthCheckToolkit_Community/wiki

# Issues and Support
Access our Issues at https://github.com/dotraphael/HealthCheckToolkit_Community/issues
