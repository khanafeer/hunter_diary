[TOC]

# Splunk Common Searches

### General

```bash
| eventcount summarize=false index=* | dedup index | fields index
```

List Source Types Metadata by index

```python
| metadata type=sourceypes index=*
```

List Source Types Metadata by index in time intervals

```shell
| metadata type=sourcetypes index=*
| eval firstTime=strftime(firstTime,"%m/%d/%y %H:%M:%S") 
| eval lastTime=strftime(lastTime,"%m/%d/%y %H:%M:%S") 
```

````python
`sysmon` | stats count by EventCode
````

```bash
| tstats <stats-function> from datamodel=<datamodel-name> where <where-conditions> by <field-list> 
```

```
`notable`
| stats count by rule_name
```

```python
`sysmon` Image=”*\\powershell.exe” OR Image=”*\\msbuild.exe” OR Image=”*\\psexec.exe” OR Image=”*\\at.exe” OR Image=”*\\schtasks.exe” OR Image=”*\\net.exe” OR Image=”*\\vssadmin.exe” OR Image=”*\\utilman.exe” OR Image=”*\\wmic.exe” OR Image=”*\\mshta.exe” OR Image=”*\\wscript.exe” OR Image=”*\\cscript.exe” OR Image=”*\\cmd.exe” OR Image=”*\\whoami.exe” OR Image=”*\\mmc.exe” OR Image=”*\\systeminfo.exe” OR Image=”*\\csvde.exe” OR Image=”*\\certutil.exe” | stats values(CommandLine) by Image
```

```
`sysmon` Image=”*\\powershell.exe” OR Image=”*\\msbuild.exe” OR Image=”*\\psexec.exe” OR Image=”*\\at.exe” OR Image=”*\\schtasks.exe” OR Image=”*\\net.exe” OR Image=”*\\vssadmin.exe” OR Image=”*\\utilman.exe” OR Image=”*\\wmic.exe” OR Image=”*\\mshta.exe” OR Image=”*\\wscript.exe” OR Image=”*\\cscript.exe” OR Image=”*\\cmd.exe” OR Image=”*\\whoami.exe” OR Image=”*\\mmc.exe” OR Image=”*\\systeminfo.exe” OR Image=”*\\csvde.exe” OR Image=”*\\certutil.exe” | stats values(CommandLine) by host

```

```
`sysmon` host=we8105desk | stats values(CommandLine) by Image _time
```

 ```
`sysmon` EventID=3 host=WE9041SRV | stats values(DestinationPort) by DestinationHostname
 ```

### Export Logs Local

```
sudo -u splunk /opt/splunk/bin/splunk search "index=* AND sourcetype!=cisco* earliest=07/3/2021:23:59:00 latest=07/4/2021:23:59:00 " -output rawdata -maxout 0 > /tmp/logs_no_fw_1
```

### Time Diff (first and last event)

```python
| stats max(_time) as maxtime min(_time) as mintime 
| eval difference=maxtime-mintime
```

```bash
index=botsv1 imreallynotbatman.com form_data="username=admin&*" sourcetype="stream:http" http_method=POST
| stats count by _time, status, form_data
| reverse
| head 2
| stats max(_time) as maxtime min(_time) as mintime 
| eval difference=maxtime-mintime
```

### Extract Text as field

```bash
index=botsv1 imreallynotbatman.com form_data="username=admin&*" sourcetype="stream:http" http_method=POST
| rex field=form_data "passwd=(?<p>\w+)" 
| dedup p 
| stats count by _time, status, form_data,p
```

```
index=windows
| rex "(?m)Caller Process Name:\s*(?<Process>.*)"
| rex "(?m)Failure Code:\s*[^\s]+\s*(?<error>.*)"
| rex "(?m)Sub Status:\s*(?<error>.*)"
```

```bash
index=botsv1 imreallynotbatman.com form_data="username=admin&*" sourcetype="stream:http" http_method=POST
| rex field=form_data "Signature string:(?<p>\w+)" 
| dedup p 
| stats count by _time, status, form_data,p
```

### Extract fields by split

```bash
index=av eventtype=symantec_ep_security
| eval fields=split(_raw,",") | eval signature=mvindex(fields,3)
| top limit=50 signature
```



# Maturity Assessment SPLs

### Sources types by index

```sh
| tstats values(sourcetype) as sourcetypes where index=* by index
| stats values(index) as indexes by sourcetypes
```

```sh
| metadata type=sourceypes index=*
```

### Accelerated data models and completion rate

```sh
| rest /services/admin/summarization by_tstats=t splunk_server=local count=0 
| eval datamodel=replace('summary.id',"DM_".'eai:acl.app'."_","") 
| join type=left datamodel 
    [| rest /services/data/models splunk_server=local count=0 
    | table title acceleration.cron_schedule eai:digest 
    | rename title as datamodel 
    | rename acceleration.cron_schedule AS cron] 
| table datamodel eai:acl.app summary.access_time summary.is_inprogress summary.size summary.latest_time summary.complete summary.buckets_size summary.buckets cron summary.last_error summary.time_range summary.id summary.mod_time eai:digest summary.earliest_time summary.last_sid summary.access_count 
| rename summary.id AS summary_id, summary.time_range AS retention, summary.earliest_time as earliest, summary.latest_time as latest, eai:digest as digest 
| rename summary.* AS *, eai:acl.* AS * 
| sort - complete
```

### Internal Log Errors

```sh
index=_internal latest=now() earliest=-7d@d source=*splunkd.log log_level!=INFO
| top limit=3 _raw by component
| sort -percent
```

### Amount of user searches by source types and index

```sh
index=_audit latest=now() earliest=-7d@d sourcetype=audittrail action=search search_id=* NOT (user=splunk-system-user ) 
| rex field=search "sourcetype\s*=\s*\"*(?<sourcetype_used>[^\s\"]+)" 
| rex field=search "index\s*=\s*\"*(?<index_used>[^\s\"]+)"
| stats count by sourcetype_used,index_used,user
| sort -count
```

### skipped searches

```sh
index=_internal latest=now() earliest=-7d@d sourcetype=scheduler status=skipped
| stats count earliest(_time) as earliest_run, latest(_time) as latest_run by savedsearch_name,status,reason
| eval earliest_run = strftime(earliest_run,"%F %T"), latest_run = strftime(latest_run,"%F %T")
| sort -count
```



# Detection Use Cases

### indexes not receiving logs

```sh
| tstats latest(_time) as latest where index=* earliest=-24h by index
| eval recent = if(latest > relative_time(now(),"-5m"),1,0), realLatest = strftime(latest,"%c")
| where recent=0
```

### MalDocs

```sh
index=windows EventCode=4688 ( New_Process_Name = "*WMIC.exe" OR  Process_Command_Line = "*whoami.exe" OR New_Process_Name ="*cmd.exe*" OR  New_Process_Name ="*powershell.exe*")  AND ( Creator_Process_Name="*winword.exe" OR  Creator_Process_Name="*excel.exe" OR  Creator_Process_Name="*powerpnt.exe")
| stats count by host,New_Process_Name,Process_Command_Line,Creator_Process_Name
```

### logon from Multiple IPs

```sh
| tstats count values(Authentication.Source_Network_Address) as multiple_src dc(Authentication.Source_Network_Address) as src_count from datamodel="Authentication"."Authentication" WHERE  (Authentication.signature_id=4624 OR Authentication.signature_id=528) Authentication.Logon_Type=2 OR Authentication.Logon_Type=10 OR Authentication.Logon_Type=3 by  Authentication.user Authentication.signature  | rename "Authentication.*" as * | search src_count>1 count >2 | search multiple_src!=unknown multiple_src!="-"
```

### logon from Multiple HOSTs

```bash
| tstats count values(Authentication.Workstation_Name) as multiple_src dc(Authentication.Workstation_Name) as src_count from datamodel="Authentication"."Authentication" WHERE  (Authentication.signature_id=4624 OR Authentication.signature_id=528) Authentication.Logon_Type=2 OR Authentication.Logon_Type=10 OR Authentication.Logon_Type=3 by  Authentication.user Authentication.signature  | rename "Authentication.*" as * | search src_count>1 count >2 | search multiple_src!=unknown multiple_src!="-"
```

### Inactive Account Activity

```
| `inactive_account_usage("90","2")` | `ctime(lastTime)` | fields + user,tag,inactiveDays,lastTime
```

```python
| tstats summariesonly=t allow_old_summaries=t count min(_time) as earliest max(_time) as latest from datamodel=Authentication where nodename="Authentication.Successful_Authentication" earliest=-1d@d latest=@d by Authentication.user 
| rename Authentication.user as user
| multireport
[| stats values(*) as * by user
 | lookup account_status_tracker user OUTPUT count as prior_count earliest as prior_earliest latest as prior_latest
 | where prior_latest < relative_time(now(), "-90d")
 | eval explanation="The last login from this user was " . (round( (earliest-prior_latest) / 3600/24, 2) ) . " days ago."
 | convert ctime(earliest) ctime(latest) ctime(prior_earliest) ctime(prior_latest) ]
[| inputlookup append=t account_status_tracker
 | stats min(earliest) as earliest max(latest) as latest sum(count) as count by user
 | outputlookup account_status_tracker
 | where this_only_exists_to_update_the_lookup='so we will make sure there are no results']
```

### Other Use Cases

```sh
| tstats `summariesonly` count from datamodel=Intrusion_Detection.IDS_Attacks where IDS_Attacks.severity=high OR IDS_Attacks.severity=critical by IDS_Attacks.src, IDS_Attacks.dest, IDS_Attacks.signature, IDS_Attacks.severity 
```

```sh
| tstats summariesonly=false values(Authentication.tag) as tag, 
values(Authentication.app) as app, 
count(eval('Authentication.action'=="failure")) as failure, 
count(eval('Authentication.action'=="success")) 
as success from datamodel=Authentication by Authentication.src 
| search success>0 | 
where failure > 5 
| `settags("access")` 
| `drop_dm_object_name("Authentication")`
```

```sh
(index=dns)  reply_code!=NOERROR |search (action=failure OR action=blocked)  |stats count by src query  |where count>50
```

```sh
sourcetype=fe_cef_syslog index=security eventtype=fe_ex "tag::eventtype"=alert act!=notified
```

```sh
index=* source="*WinEventLog:Security" (Logon_Type=2 OR Logon_Type=10 OR Logon_Type=11) NOT [| inputlookup service_accounts.csv] 
| stats values(dest)  by user
```

```sh
index=windows source=*sysmon* EventID=11 (Image=*control.exe OR Image=*excel.exe OR Image=powerpnt.exe) (TargetFilename=*.cab OR TargetFilename=*.inf) 
| stats count by Image, TargetFilename
```

```sh
index=windows source=*sysmon* EventID=1 Image=*control.exe (CommandLine=*../* AND CommandLine=*.cpl*) 
| stats count by Image, CommandLine
```

```sh
| tstats summariesonly=t allow_old_summaries=t dc(All_Traffic.dest_port) as num_dest_port dc(All_Traffic.dest_ip) as num_dest_ip from datamodel=Network_Traffic where earliest=-1h by All_Traffic.src_ip
| where (num_dest_port > 1000 OR num_dest_ip > 1000)
| search (All_Traffic.src_ip != 10.0.0.0/8 AND All_Traffic.src_ip !=172.16.0.0/12 AND All_Traffic.src_ip != 192.168.0.0/16)
```





# Dashboards

## Insights

### Event Category Count

```sh
`notable` 
| stats count by security_domain  
| sort -count
| rename security_domain   as "Threat Categories"
```

### Top 10 Event Sources

```sh
| tstats count where index=* by index | sort - count | head 10
```

### Top Notables

```sh
| `es_notable_events` | search timeDiff_type=current | stats sum(count) as count by rule_name | sort 100 - count
```

### Top Notables By Severity

```sh
`notable` | stats count by urgency 
| rename urgency as Severity
| sort -count
```



## Account Activities

### Account Locked Out

**Count**

```python
| tstats  `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management host="*" by _time All_Changes.user, All_Changes.result_id,host
| rename All_Changes.user as user , host as " locked Out  " , All_Changes.result_id as EventCode 
| `ctime(firstTime)` | `ctime(lastTime)`
| where EventCode=4740
| stats count by EventCode 
| fields - EventCode
```

**Values**

```python
| tstats  `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management host="*" by _time All_Changes.user, All_Changes.result_id,host
| rename All_Changes.user as user , host as " Host " , All_Changes.result_id as EventCode 
| `ctime(firstTime)` | `ctime(lastTime)`
| where EventCode=4740
| sort + firstTime
|rename firstTime as Time | sort -count 
| head 10000
| fields - _time EventCode lastTime count
```





### Account Created

**Count**

```python
| tstats  `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management host="*" by _time All_Changes.user, All_Changes.result_id,host
| rename All_Changes.user as user , host as " locked Out  " , All_Changes.result_id as EventCode 
| `ctime(firstTime)` | `ctime(lastTime)`
| where EventCode=4720
| stats count by EventCode 
| fields - EventCode
```

**Values**

```python
| tstats  `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management host="*" by _time All_Changes.user, All_Changes.result_id,host
| rename All_Changes.user as User , host as " Created Account In" , All_Changes.result_id as EventCode 
| `ctime(firstTime)` | `ctime(lastTime)`
| where EventCode=4720
| sort + firstTime
|rename firstTime as Time | sort -count 
| head 10000
| fields - _time EventCode lastTime count
```



### Account Deleted

**Count**

```python
| tstats  `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management   by _time All_Changes.user, All_Changes.result_id,host
| rename All_Changes.user as user , host as " locked Out  " , All_Changes.result_id as EventCode 
| `ctime(firstTime)` | `ctime(lastTime)`
| where EventCode=4726
| stats count by EventCode 
| fields - EventCode
```

**Values**

```python
| tstats  `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management  by _time All_Changes.user, All_Changes.result_id,host
| rename All_Changes.user as User , host as " Deleted in " , All_Changes.result_id as EventCode 
| `ctime(firstTime)` | `ctime(lastTime)`
| where EventCode=4726
| sort + firstTime |rename firstTime as Time 
| fields - _time EventCode count lastTime
```



### Monitoring (Created/Enabled/Disabled) Accounts

**Values**

```python
index=* EventCode=4720 OR EventCode=4722 OR  EventCode=4725 OR EventCode=4726 
| table signature src_user user 
| rename user as Target_Account 
| where src_user!=Target_Account
```



### Password Change by User

**Count**

```python
| tstats  `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management host="*" by _time All_Changes.user, All_Changes.result_id,host
| rename All_Changes.user as user , host as " Password Changed by User in" , All_Changes.result_id as EventCode 
| `ctime(firstTime)` | `ctime(lastTime)`
| where EventCode= 4723
| stats count by EventCode 
| fields - EventCode
```

**Values**

```python
index=* EventCode=4723
| stats count by user signature src_user host _time 
| rename user as user , host as " Password Changed by User in" , src_user as "Password Changed by User" 
| fields -  EventCode count lastTime
```



### Password Change by Admin

**Count**

```python
| tstats  `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management host="*" by _time All_Changes.user, All_Changes.result_id,host
| rename All_Changes.user as user , host as " Password Changed by User in" , All_Changes.result_id as EventCode 
| `ctime(firstTime)` | `ctime(lastTime)`
| where EventCode=4724
| stats count by EventCode 
| fields - EventCode
```

**Values**

```python
index=* EventCode=4724
| stats count by user signature src_user host _time 
| rename user as user , host as " Password Changed by User in" , src_user as "Password Changed by User" 
| fields -  EventCode count lastTime
```



### User login Failures

**Count**

```python
| tstats summariesonly=false count(Authentication.action) as count from datamodel="Authentication"."Authentication" where host="*"
  by Authentication.user, Authentication.signature_id ,host 
| rename Authentication.user as user , host as "Authenicated by" , Authentication.signature_id as EventCode 
| where EventCode=4625
| sort - count 
| head 10000 
| stats count by EventCode 
| fields - EventCode
```

**Values**

```python
| tstats summariesonly=false count(Authentication.action) as count from datamodel="Authentication"."Authentication" where host="*"
  by Authentication.user, Authentication.signature_id ,host
| rename Authentication.user as User , host as "Authenicated by" , Authentication.signature_id as EventCode 
| where EventCode=4625
| sort - count |rename count as "Count" | head 10000 
| fields - EventCode
```

### Top 10 Privileged Account Usage Over Time

```python
| tstats summariesonly=true count from datamodel="Authentication"."Authentication" where nodename=Authentication.Privileged_Authentication Authentication.user!=unknown by  Authentication.user |sort - count |dedup Authentication.user  |head 10
```



## Anomaly Detection

**DDOS Anomaly Dashboard**, Count of source IPs per one hour to detect DDOS anomaly

```sh
| tstats count from datamodel=Network_Traffic by _time span=1h
```

**DNS** Message Length Anomaly

```sh
index=* sourcetype=dns*
 | timechart span=12h avg(msg_length) as avg_len
```

**DNS** Anomaly Detection by Source

```sh
index=* sourcetype=dns* message_type="Query" 
| timechart span=1h limit=10 usenull=f useother=f count AS Requests by src
```

**DNS packet size Anomaly**, Increases in DNS packet size and volume

```sh
index=* sourcetype=dns* message_type="Query" 
| mvexpand query
| eval queryLength=len(query)
| stats count BY queryLength, src
| sort -queryLength, count
| table src queryLength count
| head 1000
```

**Windows Patch Status**

```sh
index=windows tag=update  host=*  
| rex field=Message "(?<Package_KB>(?<=\()[^)]*(?=\)))"
| eval format_time = strftime(_time,"%d/%m/%Y %H:%M.%S %p")
| eval patch_status = Keywords
| stats count by  patch_status
```

