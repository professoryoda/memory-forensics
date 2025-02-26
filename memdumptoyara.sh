import os
import time
import subprocess
import csv
import re
import json

WATCH_FOLDER = "/path/to/memory_dumps"  # Change to your folder
OUTPUT_FOLDER = "/path/to/analysis_results"  # Change to save analysis results
VOLATILITY_PATH = "/path/to/vol.py"  # Update with the correct path to Volatility 3

def get_volatility_plugins():
    """Retrieve available Volatility 3 plugins."""
    try:
        result = subprocess.run(
            ["sudo", "python3", VOLATILITY_PATH, "-h"], 
            capture_output=True, text=True, check=True
        )
        lines = result.stdout.split("\n")
        plugins = []
        collect = False
        for line in lines:
            if "Plugins" in line:
                collect = True
                continue
            if collect and line.strip():
                plugin = line.split()[0]
                plugins.append(plugin)
        return plugins
    except subprocess.CalledProcessError as e:
        print(f"Error fetching plugins: {e}")
        return []

def analyze_memory_dump(mem_file):
    """Runs Volatility analysis on a memory dump and collects plugin outputs."""
    print(f"Analyzing {mem_file}...")
    results = {}
    plugins = get_volatility_plugins()
    
    for plugin in plugins:
        command = ["sudo", "python3", VOLATILITY_PATH, "-f", mem_file, plugin]
        print(f"Running: {' '.join(command)}")

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            output = result.stdout if result.stdout else "No Output"
            results[plugin] = output

        except subprocess.TimeoutExpired:
            print(f"Timeout for plugin: {plugin}")
            results[plugin] = "Timeout"

        except Exception as e:
            print(f"Error running {plugin}: {e}")
            results[plugin] = f"Error: {str(e)}"
    
    return results

def extract_suspicious_processes(pslist_output):
    """Extracts processes whose PPID traces back to explorer.exe."""
    process_tree = {}
    suspicious_procs = []

    # Parse pslist output
    lines = pslist_output.split("\n")
    for line in lines:
        match = re.match(r"(\d+)\s+(\d+)\s+(\S+)", line)
        if match:
            pid, ppid, name = match.groups()
            process_tree[int(pid)] = {"ppid": int(ppid), "name": name}

    # Trace process trees
    for pid, info in process_tree.items():
        ppid = info["ppid"]
        while ppid in process_tree:
            if process_tree[ppid]["name"].lower() == "explorer.exe":
                suspicious_procs.append((pid, info["name"]))
                break
            ppid = process_tree[ppid]["ppid"]

    return suspicious_procs

def dump_process_memory(mem_file, pid):
    """Dumps the memory of a given process using Volatility's procdump plugin."""
    dump_path = os.path.join(OUTPUT_FOLDER, f"process_{pid}.dmp")
    command = ["sudo", "python3", VOLATILITY_PATH, "-f", mem_file, "procdump", "--pid", str(pid), "--dump-dir", OUTPUT_FOLDER]
    
    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
        return dump_path
    except subprocess.CalledProcessError as e:
        print(f"Error dumping memory for PID {pid}: {e}")
        return None

def extract_strings(dump_file):
    """Extracts strings from the dumped memory file."""
    strings_output = os.path.join(OUTPUT_FOLDER, f"{os.path.basename(dump_file)}.strings")
    command = ["strings", dump_file]

    try:
        with open(strings_output, "w") as f:
            subprocess.run(command, stdout=f, text=True, check=True)
        return strings_output
    except subprocess.CalledProcessError as e:
        print(f"Error extracting strings: {e}")
        return None

def generate_yara_rule(strings_file):
    """Generates a basic YARA rule from extracted strings."""
    yara_rule_file = os.path.join(OUTPUT_FOLDER, f"{os.path.basename(strings_file)}.yara")
    strings = []

    try:
        with open(strings_file, "r") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if len(line) > 10 and i < 20:  # Limit to 20 unique strings
                    strings.append(f'$str{i} = "{line}"')

        if strings:
            rule_content = f"""rule SuspiciousProcess {{
    strings:
        {chr(10).join(strings)}
    condition:
        any of them
}}"""
            with open(yara_rule_file, "w") as f:
                f.write(rule_content)
            return yara_rule_file
    except Exception as e:
        print(f"Error generating YARA rule: {e}")
        return None

def save_results_to_csv(results, output_file):
    """Saves analysis results to CSV."""
    keys = list(results.keys())
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerow(results)

def watch_folder():
    """Watches a folder for new memory dumps and analyzes them."""
    processed_files = set()
    
    while True:
        files = [f for f in os.listdir(WATCH_FOLDER) if f.endswith(".mem")]

        for file in files:
            file_path = os.path.join(WATCH_FOLDER, file)
            if file_path not in processed_files:
                processed_files.add(file_path)

                # Step 1: Run Volatility plugins
                results = analyze_memory_dump(file_path)

                # Step 2: Identify malicious processes
                if "pslist" in results:
                    suspicious_procs = extract_suspicious_processes(results["pslist"])
                    
                    for pid, proc_name in suspicious_procs:
                        print(f"Suspicious Process Found: {proc_name} (PID: {pid})")
                        
                        # Step 3: Dump process memory
                        dump_file = dump_process_memory(file_path, pid)
                        
                        if dump_file:
                            # Step 4: Extract strings
                            strings_file = extract_strings(dump_file)
                            
                            # Step 5: Generate YARA rules
                            if strings_file:
                                yara_rule_file = generate_yara_rule(strings_file)
                                print(f"Generated YARA Rule: {yara_rule_file}")

                # Step 6: Save full results to CSV
                csv_output = os.path.join(OUTPUT_FOLDER, f"{file}.csv")
                save_results_to_csv(results, csv_output)
                print(f"Analysis complete for {file}, results saved to {csv_output}")

        time.sleep(10)  # Check every 10 seconds

if __name__ == "__main__":
    watch_folder()
