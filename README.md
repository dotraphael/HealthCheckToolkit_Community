# HealthCheckToolkit_Community
This repository contains the scripts used to collect data from a SCCM environmnet as per the blog post from https://thedesktopteam.com/raphael/sccm-sccm-healthcheck/

How to:
1- Download all files and save to a location on the hard drive (You should have 5 files: CollectData.ps1, HealthCheckClasses.dll, Messages.xml, SCCMDefaultValues.xml and SCCMRulesOverride.xml)
2- Open PowerShell as Administrator and If prompted by UAC, click Yes
3- Navigate to the folder where you have extracted the files
4- Type: .\CollectData.ps1 -AuthorizedSiteCodes '001' -MessageFilePath .\Messages.xml -RulesOverrideFilePath .\SCCMRulesOverride.xml -DefaultValuesOverrideFilePath .\SCCMDefaultValues.xml
4.1 - AuthorizedSiteCodes should have the SCCM Site Code. Remember to change it
5- Once the collection of the files have been created, a zip file will be created on the Desktop and the collected XML files will be saved on C:\Temp\SCCMHealthCheck

Notes:
1- Depending on the size of the environment, the tool may take couple of hours to run
2- Send an e-mail to me (raphael AT perez DOT net DOT br) with the HealthCheck zip file created by the tool (if the file is too big, upload it to somewhere and send me the link)
2.1- When sending the e-mail, don't forget to give me your details, like Name and SCCM Site Information so i can check it against the generated report (just to be sure the tool is doing what it is supposed to do). And if you're collecting data from a production environment, send me the name of the company as well.
3- I'll run it against our SCCM HealthCheck Reporting Tool and will generate a report in word format and will reply it to your e-mail. There will be no manual intervention, so the what the solution find i'll send to you
3.1- As it is a free service, don't expect a reply "ASAP style". I'll do my best to reply to you within couple of working days, but depending on my work schedule, it may take more time. Expect at least one week for reply. If not, send me an e-mail again.
4- Once i reply to your e-mail with the report, all data will be erased. i'll not keep any of the data you've send to me.
5- This is "as is" service at the moment, If something does not work, let me know and i'll try to fix, but don't expect a "premier" support. If you want a "premier" support and a only "on-prem" execution, you can use our paid services, available at https://www.rflsystems.co.uk/software/healthcheck-toolkit/
