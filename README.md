# memory-forensics

Memorydump2yara is an automated Volatility 3 malware analysis pipeline that:
	Watches a folder for new memory dump files (.mem).
	Runs Volatility 3 against each memory dump and saves results.
	Identifies malicious processes:
  	•	Extracts all processes (pslist).
  	•	Traces each process’s parent (PPID) until it reaches explorer.exe.
  	•	Flags suspicious processes that originated from explorer.exe (indicative of human-operated malware).
	Dumps memory for flagged processes using procdump.
	Extracts strings from dumped memory.
	Generates YARA rules based on extracted strings.
