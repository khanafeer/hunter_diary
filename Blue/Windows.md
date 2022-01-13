# Windows Notes



## Top Logon Event IDs

### Account-Related Events

| Event ID | Description                                                  | Links                                                        |
| -------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 4768     | The successful issuance of a TGT shows that a user account was authenticated by the domain controller. The Network Information section. of the event description contains additional information about the remote host in the event of a remote logon attempt. | [more details](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4768) |
| 4769     | A service ticket was requested by a user account for a specified resource.<br/>This event description shows the source IP of the system that made the<br/>request, the user account used, and the service to be accessed. These events<br/>provide a useful source of evidence as they track authenticated user access<br/>across the network. | [more details](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4769) |
| 4770     | A service ticket was renewed. The account name, service name, client<br/>IP address, and encryption type are recorded. |                                                              |
| 4776     | This event ID is recorded for NTLM authentication attempts. The Network Information section of the event description contains additional information about the remote host in the event of a remote logon attempt. | [more details](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4776) |
| 4624     | An account was successfully logged on. Type 2 indicates an interactive (usually local) logon, whereas a Type 3 indicates a remote or network logon.<br/>The event description will contain information about the host and account<br/>name involved. For remote logons, focus on the Network Information section of the event description for remote host information. Correlation with<br/>the associated 4768, 4769, or 4776 events may yield additional details about<br/>a remote host. Discrepancies in the record entry between the recorded<br/>hostname and its assigned IP address may be indicative of Server Message Block (SMB) relay attacks, where an attacker relays a request from<br/>one system using an IP address not associated with that system. | [more details](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624) |
| 4625     | A failed logon attempt. Large numbers of these throughout a network<br/>may be indicative of password guessing or password spraying attacks.<br/>Again, the Network Information section of the event description can provide valuable information about a remote host attempting to log on to the<br/>system. Note that failed logons over RDP may log as Type 3 rather than<br/>Type 10, depending on the systems involved. | [more details](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625) |
| 4648     | A logon was attempted using explicit credentials. When a user attempts<br/>to use credentials other than the ones used for the current logon session(including bypassing User Account Control [UAC] to open a process with<br/>administrator permissions), this event is logged. | [more details](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4648) |
| 4672     | This event lets you know whenever an account assigned any "administrator equivalent" user rights logs on. For instance you will see event 4672 in close proximity to logon events ([4624](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624)) for administrators since administrators have most of these admin-equivalent rights. |                                                              |
|          |                                                              |                                                              |
|          |                                                              |                                                              |

### Object Access

Computer Configuration ➪ Policies ➪ Windows Settings ➪ Security Settings ➪ Advanced Audit Policy Configuration ➪ Audit Policies ➪ Object Access ➪ Audit File Share

| Event ID | Description                                                  | Link |
| -------- | ------------------------------------------------------------ | ---- |
| 5140     | A network share object was accessed. The event entry provides<br/>the account name and source address of the account that accessed the<br/>object. Note that this entry will show that the share was accessed but<br/>not what files in the share were accessed. A large number of these<br/>events from a single account may be an indicator of an account being<br/>used to harvest or map data on the network. |      |
| 5142     | A network share object was added.                            |      |
| 5143     | A network share object was modified.                         |      |
| 5144     | A network share object was deleted.                          |      |
| 5145     | A network share object was checked to see whether the client can be<br/>granted desired access. Failure is only logged if the permission is denied<br/>at the file share level. If permission is denied at the NTFS level, then no<br/>entry is recorded. |      |
| 4698     | A scheduled task was created. The event description contains the user<br/>account that created the task in the Subject section. XML details of the<br/>scheduled task are also recorded in the event description under the Task<br/>Description section and include the Task Name. |      |
| 4699     | A scheduled task was deleted. The Subject section of the event description<br/>contains the Account Name that deleted the task as well as the Task Name |      |
| 4700     | A scheduled task was enabled. See Event ID 4698 for additional details. |      |
| 4701     | A scheduled task was disabled. See Event ID 4698 for additional details. |      |
| 4702     | A scheduled task was updated. The user who initiated the update appears<br/>in the Subject section of the event description. The details of the task after<br/>its modification are listed in the XML in the event description. Compare with<br/>previous Event ID 4702 or 4698 entries for this task to determine what<br/>changes were made. See Event ID 4698 for additional details |      |
| 4656     | A handle to an object was requested. When a process attempts to gain a<br/>handle to an audited object, this event is created. The details of the object<br/>to which the handle was requested and the handle ID assigned to the<br/>handle are listed in the Object section of the event description. Success or<br/>failure of the handle request will be indicated in the Keywords field. The<br/>account used to request the handle, as well as that account’s associated<br/>Logon ID, is recorded in the Subject section of the event description. The<br/>details of the process requesting the handle are listed under the<br/>Process Information section of the event description. |      |
| 4657     | A registry value was modified. The user account and process responsible for<br/>opening the handle are listed in the event description. The Object section<br/>contains details of the modification, including the Object Name field, which<br/>indicates the full path and name of the registry key where the value was<br/>modified. The Object Value Name field contains the name of the modified<br/>registry key value. Note that this event generates only when a key value is<br/>modified, not if the key itself is modified. |      |
| 4658     | The handle to an object was closed. The user account and process<br/>responsible for opening the handle are listed in the event description. To<br/>determine the object itself, refer to the preceding Event ID 4656 with the<br/>same Handle ID. |      |
| 4660     | An object was deleted. The user account and process responsible for<br/>opening the handle are listed in the event description. To determine the<br/>object itself, refer to the preceding Event ID 4656 with the same Handle ID. |      |
| 4663     | An attempt was made to access an object. This event is logged when a<br/>process attempts to interact with an object, rather than just obtain a handle<br/>to the object. This can be used to help determine what types of actions may<br/>have been taken on an object (for example, read only or modify data). See<br/>Event ID 4656 for additional details. |      |
|          |                                                              |      |
|          |                                                              |      |

### Use-cases

use-case 1

```
A series of failed 4776 events with Error Code C000006A (the password is invalid) followed by an Error Code C0000234 (the account is locked out) may
be indicative of a failed password guessing attack (or a user who has simply
forgotten the account password). Similarly, a series of failed 4776 events followed by a successful 4776 event may show a successful password guessing
attack. The presence of Event ID 4776 on a member server or client is indicative of a user attempting to authenticate to a local account on that system
and may in and of itself be cause for further investigation.
```



 