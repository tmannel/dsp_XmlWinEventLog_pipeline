$statement_3 = 
| from receive_from_forwarders("forwarders:all"); 

| from $statement_3 
| where source_type="XmlWinEventLog:System" AND body!="" 
| eval body=cast(body, "string") 
| rex max_match=0 field=body "<EventID.*?>(?<EventCode>.+?)</EventID>.*<EventRecordID>(?<EventRecordID>.+?)</EventRecordID>.*<Execution ProcessID='(?<ProcessID>.+?)' ThreadID='(?<ThreadID>.+?)'/><Channel>(?<Channel>.+?)</Channel><Computer>(?<host>.+?)</Computer>.*"; 

| from $statement_3 
| where source_type="XmlWinEventLog:Application" AND body!=""; 

| from $statement_3 
| where source_type="XmlWinEventLog:Security" AND body!="" 
| eval body=cast(body, "string") 
| rex max_match=0 field=body "<EventID.*?>(?<EventCode>.+?)</EventID>.*<EventRecordID>(?<EventRecordID>.+?)</EventRecordID>.*<Channel>(?<Channel>.+?)</Channel><Computer>(?<host>.+?)</Computer>.*" 
| rex max_match=0 field=body "<Data Name='(?<key>.*?)'>(?<value>.*?)<\\/Data>" 
| eval size=mvrange(0, length(key)-1), results=create_map() 
| into splunk_enterprise_indexes("71fed15a-41ec-462f-9420-5a3301084ecb", "dsp_windows_mannel_rex", "dsp_windows_mannel_rex");
