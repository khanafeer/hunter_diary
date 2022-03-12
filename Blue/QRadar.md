[TOC]

# Troubleshooting

## Wincollect Agent

- Check Wincollect agent logs.

```sh
C:\Program Files\IBM\WinCollect\logs\*
```

- Check ports (**514** and **8413**) status (maybe dropped by FW).
- If Wincollect has public key error.

```sh
1.Search the agent in the Wincollect UI and rename the "hostname" field to something different, for example agent_old. Save changes. (From Qradar Web UI)
2.Delete the agent. (From Qradar Web UI)
3.Delete the agent folder under /store/configservices/wincollect/configserver/<agentname> ( At QRadar Server via SSH)
4.Remove the **ConfigurationServer.PEM** file from the config folder in the agent which is in C:\Program Files\IBM\WinCollect\config. (At the Windows machine that hosts the agent)
5. start the Wincollect service. (At the Windows machine that hosts the agent)
```

## Applications

```
```



## restart QRadar applications

1. Log in to QRadar.
2. From the **☰** menu, click **Interactive API for developers**. The interactive API is displayed. QRadar ships with several API versions, with the latest version being indicated by the highest version number. QRadar Support always recommends using the most recent API vesion (highest number).
3. Select the **/gui_app_framework** endpoint.
4. Click **/applications**:
5. Scroll to bottom, click the **Try It Out** button. The GET command returns the **application_id** for the application. Optionally, you can use the command line and */opt/qradar/support/qapp_utils730.py* to retrieve the application ID.
6. Click the **POST** tab.
7. In the **application_id** field, type the application id number.
8. To stop or start your application, type one of the following options:
   1. **STOPPED** - this value stops the application after you click the **Try it Out** button.
   2. **RUNNING** - this value starts the application after you click the **Try it Out** button.
9. Verify the response field returned for the command displays **200 (OK)**. The response code returned allows you to verify that the command was successfully sent to the QRadar API. This status can be confirmed using the */opt/qradar/support/qapp_utils730.py* utility.





# Common AQL Queries

```sql
SELECT * FROM events LAST 10 MINUTES
SELECT sourceip,destinationip FROM events LAST 24 HOURS
SELECT * FROM events START '2017 01 01 9:00:00' STOP '2017 01 01 10:20:00'


SELECT * FROM events limit 5 LAST 24 HOURS
SELECT * FROM events ORDER BY magnitude DESC LAST 24 HOURS
SELECT * FROM events WHERE magnitude >= 3 


SELECT * FROM events WHERE sourceip = '192.0.2.0' AND destinationip = '198.51.100.0' START '2017 01 01 9:00:00' STOP '2017 01 01 10:20:00'
SELECT * FROM events WHERE INCIDR('192.0.2.0/24',sourceip)


SELECT * FROM events WHERE username LIKE '%roul%'  #CaseSensetive
SELECT * FROM events WHERE username ILIKE '%ROUL%' #CaseInsensetive


SELECT sourceip,category,credibility FROM events WHERE (severity > 3 AND category = 5018)OR (severity < 3 AND credibility > 8)


SELECT * FROM events WHERE TEXT SEARCH 'firewall' #have "firewall" text in search


#Aggregations
SELECT sourceip, AVG(magnitude)FROM events GROUP BY sourceip
SELECT sourceip, FIRST(magnitude)FROM events GROUP BY sourceip #first entry of the rows in the aggregate.

#functions
SELECT APPLICATIONNAME(applicationid) AS 'Name of App' FROM flows

ASSETHOSTNAME(sourceip)
ASSETHOSTNAME(sourceip, domainid)
SELECT ASSETHOSTNAME(destinationip, NOW()) AS 'Host Name' FROM events

ASSETPROPERTY('Unified Name', sourceIP, domainId)
SELECT ASSETPROPERTY('Location',sourceip) AS Asset_location,COUNT(*) AS 'event count' FROM eventsGROUP BY Asset_locationLAST 1 days

SELECT logsourceid, LOGSOURCENAME(logsourceid) AS 'Name of log source', LOGSOURCEGROUPNAME(devicegrouplist) AS 'Group Names', LOGSOURCETYPENAME(devicetype) AS 'Devices' FROM events GROUP BY logsourceid
```

# Tricks

- **Unlock locked hosts**

```
/opt/qradar/bin/runjava.sh com.ibm.si.security_model.authentication.AuthenticationLockoutCommandLineTool --remove-all-ips
```

- **Regex**


```
"UserId":"(.*?)"
```

- **export rules**

```
/opt/qradar/support/extractRules.py -o <filename>
```

- Check EPS for each log source ex: Windows Event Logs

  ```sql
  SELECT LOGSOURCETYPENAME(devicetype) AS "Log Source", SUM(eventcount) AS "Number of Events in Interval", SUM(eventcount) / (60*60*2) AS "EPS in Interval", UniqueCount(sourceip) AS 'Count of SourceIps',UniqueCount(LOGSOURCENAME(logsourceid)) AS 'Count of sender stations'  FROM events GROUP BY "Log Source" ORDER BY "EPS in Interval" DESC START '2022-01-25 1:30' STOP '2022-01-25 3:30'
  
  ```

  - we divide by 300 in the AQL because the time interval is 5 minutes 

- Check EPS for each Device

  - ```mssql
    SELECT LOGSOURCENAME(logsourceid) AS "Log Source", SUM(eventcount) AS "Number of Events in Interval", SUM(eventcount) / (60*60*24) AS "EPS in Interval" FROM events GROUP BY "Log Source" ORDER BY "EPS in Interval" DESC LAST 1 DAYS
    ```

  - ```mysql
    START '2021-04-21 08:00' STOP '2021-04-21 16:00'
    ```

  - we divide by 300 in the AQL because the time interval is 5 minutes 

  - Export AS CSV


- Event Names and Associated EPS and Log source type

 ```sql
select QIDNAME(qid) AS 'Event Name', "EventID" As 'Event ID', sum(eventcount) AS 'Count', SUM(eventcount) / (60*60*24) As 'EPS for EID', UniqueCount(LOGSOURCENAME(logsourceid)) AS 'Count of sender stations' , UniqueCount(sourceip) AS 'Count of SourceIps',LOGSOURCETYPENAME(devicetype) AS 'LOGSOURCETYPENAME' from events GROUP BY QIDNAME(qid) ORDER BY "EPS for EID" DESC last 1 DAYS
 ```

- Average Payload Size

  ```sql
  select avg(strlen(payload)) AS 'Average Log size', sum(eventcount) AS 'eventCount' , eventCount / (60*60*2) AS "EPS in Interval" ,LOGSOURCEtypename(devicetype)  from events group by devicetype last 2 hours
  
  ```

- Terminal Command

```bash
/opt/qradar/support/jmx.sh -p 7799 -b "com.q1labs.ariel:application=ecs-ep.ecs-ep,type=Database writer,a1=events-2" | grep "AveragePayloadSize\|AverageRecordSize"
```

- Full info about ecs-ep ex: Dropped Records Count, Stored Record Count,Time Online

  ```bash
  /opt/qradar/support/jmx.sh -p 7799 -b "com.q1labs.ariel:application=ecs-ep.ecs-ep,type=Database writer,a1=events-2"
  ```

  - Elasped Time sience start of ecs-ep

    ```bash
    systemctl status ecs-ep | grep Active
    ```

- Traffic Capture for 180 Second

```bash
tcpdump -G 180 -W 1 -w Capture180.pcap -i ens33 'port 514'
```

EPS for some log sources

```sql
SELECT LOGSOURCENAME(logsourceid) AS "Log Source",DATEFORMAT( devicetime, 'dd-MM-yyyy') AS "Date_log", SUM(eventcount) AS "Number of Events in Interval", SUM(eventcount) / 86400 AS "EPS in Interval" FROM events WHERE "Log Source" ILIKE '%office%' OR "Log Source" ILIKE '%etokai%' GROUP BY "Log Source" ORDER BY "EPS in Interval" DESC LAST 24 HOURS
```

```sql
SELECT DATEFORMAT( devicetime, 'dd-MM-yyyy') AS "Date_log", LOGSOURCENAME(logsourceid) AS "Log Source", SUM(eventcount) AS "Event Count" FROM events WHERE "Log Source" ILIKE '%office%' OR "Log Source" ILIKE '%etokai%' GROUP BY "Date_log","Log Source" ORDER BY "Date_log" START '2021-01-01 00:00:00' STOP '2021-02-10 00:00:00'
```

EPS for EventIDs

```sql
SELECT QIDNAME(qid) AS 'Event Name' ,"EventID" As 'Event ID', SUM(eventcount) As 'Count of events', SUM(eventcount) / 300 As 'EPS for EID' from events GROUP BY  QIDNAME(qid) ORDER BY "EPS for EID" DESC last 60 minutes
```

```sql
SELECT QIDNAME(qid) AS 'Event Name' ,"EventID" As 'Event ID', SUM(eventcount) As 'Count of events', SUM(eventcount) / (300 * 10) As 'EPS for EID' from events WHERE LOGSOURCENAME(logsourceid) ILIKE '%apex%' GROUP BY  QIDNAME(qid) ORDER BY "EPS for EID" DESC last 10 days
```

Subquey

```sql
SELECT * FROM events WHERE username IN (SELECT username FROM events LIMIT 10 LAST 5 MINUTES) LAST 24 HOURS

SELECT * FROM EVENTS WHERE sourceip IN (SELECT destinationip FROM events)
```

Get Number of offenses

```
SELECT QIDNAME(qid) as 'Event Name',LONG(COUNT()) FROM events WHERE qid = 28250369 GROUP BY "Event Name" LAST 24 HOURS
```

```
SELECT RULENAME("rule_id") as 'Rule Name',LONG(COUNT()) FROM events WHERE qid = 28250369 GROUP BY "Rule Name" LAST 7 days
```







 
