# SPDX-FileCopyrightText: Copyright (c) 2025, SxB. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
import math
import os
import subprocess
from dotenv import load_dotenv

from computer import Computer
import pandas as pd
import asyncio
import requests
import time
import os
import subprocess
import select
 

from cyber_agent_ioc.config_settings import (
    HOSTNAME,
    USER,
    SSH_KEY_PATH,
    URL_LUME_SDK,
    VM_NAME,
    VM_PATH_LOG,
    LOCAL_PATH_LOG,
    VM_PATH_PCAP,
    LOCAL_PATH_PCAP,
    CONTEXT_WINDOWS
)

load_dotenv() 

logger = logging.getLogger("aiq_cyber_agent_ioc")
 

def check_vm_running(vm_name: str, base_url=URL_LUME_SDK):
    """
    Checks if the VM with the given name is running by querying the Lume API.
    Raises an Exception with 'Error VM not running' if the status is not 'running'.
    """
    url = f"{base_url}/{vm_name}"
    print(url)
    try:
        response = requests.get(url, timeout=5)
        # Raise an error for any non-successful HTTP status code
        response.raise_for_status()
        data = response.json()
        status = data.get("status")
        logger.info(f"VM '{vm_name}' status: {status}")
        if status == "running":
            #Run all script in background
            run_tcpdump_dns_background()
        if status != "running":
            # Raise an error if the VM is not running
            raise Exception("Error VM not running")
        return True
    except requests.RequestException as e:
        # Handle network or HTTP errors
        logger.error(f"API request failed: {e}")
        raise
    except Exception as e:
        # Handle VM status or JSON errors
        logger.error(e)
        raise

def get_file_via_scp(remote_path,local_path):
    #ssh-keygen -t ed25519 -f ~/.ssh/keys_vm_lume
    #ssh-copy-id -i ~/.ssh/keys_vm_lume lume@192.168.65.4
    #ssh -i ~/.ssh/keys_vm_lume lume@192.168.65.4
    # Commande SCP
    scp_cmd = [
        "scp",
        "-i", SSH_KEY_PATH,
        f"{USER}@{HOSTNAME}:{remote_path}",
        local_path
    ]

    # Exécution
    result = subprocess.run(scp_cmd, check=True)
    logger.info("File downloaded:", local_path)

def limit_stdout_for_llm(stdout, max_chars=CONTEXT_WINDOWS):
    """Limite la sortie à max_chars caractères pour la fenêtre de contexte du LLM."""
    if len(stdout) > max_chars:
        # On garde la fin (ou le début) selon ce qui est le plus pertinent
        return stdout[-max_chars:]
    else:
        return stdout
    return stdout

def run_cmd_vm_timeout(cmd, timeout=5):
    nb_chars = int(CONTEXT_WINDOWS) * 4
    ssh_cmd = [
        "ssh",
        "-t",
        "-i", os.path.expanduser(SSH_KEY_PATH),
        f"{USER}@{HOSTNAME}",
        cmd
    ]
    print(ssh_cmd)
    output = ""
    start = time.time()
    proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        while True:
            # On attend que quelque chose soit lisible sur stdout, timeout de 0.5s
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if ready:
                line = proc.stdout.readline()
                if not line:
                    break
                output += line
            if proc.poll() is not None:
                break
            if time.time() - start > timeout:
                proc.terminate()
                break
        # On lit le reste du buffer
        output += proc.stdout.read()
        stderr = proc.stderr.read()
        if stderr:
            logger.error("Error : %s", stderr)
        stdout_limited = limit_stdout_for_llm(output, max_chars=nb_chars)
        return stdout_limited
    except Exception as e:
        print("Erreur SSH :", e)
        return -1


def run_cmd_vm(cmd,timeout=5):
    
    #Compute approximatively the number of char from tokens
    nb_chars = int(CONTEXT_WINDOWS)*4

    ssh_cmd = [
        "ssh",
        "-i", os.path.expanduser(SSH_KEY_PATH),
        f"{USER}@{HOSTNAME}",
        cmd
    ]
    print(ssh_cmd)
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True,timeout=timeout)
        logger.debug("Output  : %s", result.stdout)
        if result.stderr:
            logger.error("Error : %s", result.stderr)
        
        #return result.returncode
        stdout_limited = limit_stdout_for_llm(result.stdout, max_chars=nb_chars)
        return stdout_limited
    except Exception as e:
        print("Erreur SSH :", e)
        return -1

async def get_system_logs(lastime:int):
    # Start a local macOS VM with a 1024x768 display
    async with Computer(os="macos", verbosity=logging.INFO, display="1024x768",telemetry_enabled=False) as computer:
        data_log = [ ]
        #result = await computer.interface.run_command("whoami")
        await computer.interface.run_command(f"log show --last {lastime}m > {VM_PATH_LOG}")

        get_file_via_scp(VM_PATH_LOG,LOCAL_PATH_LOG)

        # 3. (Optionnel) Lire et afficher le contenu du fichier téléchargé
        with open(LOCAL_PATH_LOG, "r") as f:
            data_log = f.read()
            # faire un tri pour garder que les logs mDNSResponder ou autre
            # bluetoothd, accountsd, airportd
            print("System log :\n", data_log)

        #Add log into dataFrame or other
        
        #await install_dnsmonitor(computer)
        # limit to 500 char for begin
        return data_log[:500]
    
async def get_system_logs_test(lastime:int):
    # Start a local macOS VM with a 1024x768 display
    async with Computer(os="macos", verbosity=logging.INFO, display="1024x768",telemetry_enabled=False) as computer:
        data_log = [ ]

        print(dir(computer))
        import sys
        sys.exit()
        
        #result = await computer.interface.run_command("whoami")
        await computer.interface.run_command(f"log show --last {lastime}m > {VM_PATH_LOG}")

        get_file_via_scp(HOSTNAME,USER,SSH_KEY_PATH,VM_PATH_LOG,LOCAL_PATH_LOG)

        # 3. (Optionnel) Lire et afficher le contenu du fichier téléchargé
        with open(LOCAL_PATH_LOG, "r") as f:
            data_log = f.read()
            # faire un tri pour garder que les logs mDNSResponder ou autre
            # bluetoothd, accountsd, airportd
            print("System log :\n", data_log)

        #Add log into dataFrame or other
        
        #await install_dnsmonitor(computer)
        # limit to 500 char for begin
        return data_log[:50]

async def get_network_dns_logs_test(interface="en0",ct_packet=1):
    # Start a local macOS VM with a 1024x768 display
    async with Computer(os="macos", verbosity=logging.INFO, display="1024x768",telemetry_enabled=False) as computer:
        data_pcap = [ ]
        cmd = f"sudo tcpdump -nnni {interface} udp port 53 -c {ct_packet} -w {VM_PATH_PCAP}"
        print(cmd)
        await computer.interface.run_command(cmd)

        get_file_via_scp(VM_PATH_PCAP,LOCAL_PATH_PCAP)

        #Add log into dataFrame or other
        
        #await install_dnsmonitor(computer)
        # limit to 500 char for begin
        return data_pcap[:500]


async def get_live_system_logs(last_time: int = 1):
    cmd = f"/usr/bin/log show --last {last_time}m"
    result = run_cmd_vm(cmd)
    return result

def get_data_tmp_file_txt(local_path):
    with open(local_path, "r") as f:
        data = f.read()
        logger.debug(f"data :\n{data}")

async def get_live_network_traffic(interface="en0", ct_packet=1, timeout=5):
    tcpdump_cmd = f"sudo tcpdump -l -nnni {interface} not port 22 -c {ct_packet}"
    result = run_cmd_vm(tcpdump_cmd, timeout=10)
    await asyncio.sleep(timeout)
    return result

async def run_tcpdump_dns_background():
    run_tcpdump_background = f"sudo tcpdump -n -i any port 53 -tttt > /tmp/dns_tcpdump.log &"
    result = run_cmd_vm(run_tcpdump_background, timeout=10)
    logger.info(result)

async def get_network_traffic(interface="en0", ct_packet=1, timeout=5):
    tcpdump_cmd = f"sudo tail -n 500 /tmp/dns_tcpdump.log"
    result = run_cmd_vm(tcpdump_cmd, timeout=10)
    await asyncio.sleep(timeout)
    return result


async def get_live_dns_traffic(timeout=8):
    dns_monitor_cmd = "sudo /Applications/DNSMonitor.app/Contents/MacOS/DNSMonitor"
    result = run_cmd_vm_timeout(dns_monitor_cmd, timeout=timeout)
    return result

async def get_live_process_monitor(timeout=7, filter=""):
    if filter:
        process_monitor_cmd = (
            f"sudo /Applications/ProcessMonitor.app/Contents/MacOS/ProcessMonitor --pretty --filter {filter}"
        )
    else:
        process_monitor_cmd = (
            "sudo /Applications/ProcessMonitor.app/Contents/MacOS/ProcessMonitor --pretty"
        )
    result = run_cmd_vm_timeout(process_monitor_cmd, timeout=timeout)
    return result

async def main():
        check_vm_running(VM_NAME)
        #await get_system_logs_test(1)
        result  = run_cmd_vm('ls -l')
        result = await get_live_system_logs(5)
        print(result)
        result = await get_live_network_traffic(ct_packet=10)
        print(result)
        result = await get_live_dns_traffic()
        print(result)
        result = await get_live_process_monitor()
        print(result)
        #await get_network_dns_logs_test()

if __name__ == '__main__':
    asyncio.run(main())
