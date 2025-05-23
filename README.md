#CyberAgentIOC ##NVIDIAHackathon #AI

## Cyber agent for detecting very small Indice Of Compromission on macos system

Cyber agent for detecting very small Indicators Of Compromise on macOS systems

In general, systems can be compromised by motivated actors seeking confidential information. Today, several tools exist to detect compromise artifacts or IOCs (Indicators Of Compromise). However, attacks are increasingly sophisticated and generate very weak signals in current operating systems (log deletion, remote exploits executed only in RAM, process injection, rootkits, zero-day exploits...).

The general idea is to use AI agents to check events in logs, network requests, DNS, and to correlate very weak signal events. For example, a stealthy DNS request linked to a process identified as non-suspicious by traditional tools like YARA, process hashes, but the succession of repeated connections sends an alert to an operator. The operator is then responsible for validating whether or not there has been a compromise.

Here, this is just a POC (Proof Of Concept), showing that AI agents, by collaborating together and each having their own specialty, can pool their efforts to detect very discreet compromises. Here, the POC uses a VM to develop the agents; it is also possible to control full operating systems via AI agents in high-performance virtual containers with near-native speed on Apple Silicon. Here, we used SSH for speed, but in the future, other methods may be used.[UA Agent](https://github.com/trycua/cua)
 

![Overview of Cyber Agent IOC](img/overview.png "Overview of Cyber Agent IOC").


### How to install 

This is a project that uses the UV tool and the LUME tool on macOS, which will launch the macOS VM.
You can use it with the Pylume tool, together with the Tua computer tool from your GitHub link.

```
git clone https://github.com/rag_agentic/cyber_agent_ioc
cd cyber_agent_ioc
# Clone the repo:
git clone https://github.com/NVIDIA/aiqtoolkit
cd aiqtoolkit

# Initialize the Git repository:
git submodule update --init --recursive

# Download the datasets:
git lfs install
git lfs fetch
git lfs pull

# Create a Python environment:
uv venv --seed .venv
source .venv/bin/activate
uv sync --all-groups --all-extras

#First, you should start the VM
lume run macos-sequoia-cua_latest
lume stop macos-sequoia-cua_latest

# Verify the library installation:
aiq --help
aiq --version
cd ..
uv pip install  ./aiqtoolkit/'.[langchain]'
uv pip install  ./aiqtoolkit/'.[profiling]'
uv pip install  ./src/cyber_agent_ioc/''
```

### TODO LIST

- Add an MCP client to query the VirusTotal site and use the MCP VirusTotal server.
- Add an MCP client to check YARA rules on running processes and trigger analysis in case of suspicion.
- Improve the prompts to better target the analyses.
- Use tools other than SSH, such as a global session with the Computer tool; the problem is that launching the VM takes time or it must always be running, even when the agent is stopped.
- Use AI agents from [c/ua](https://github.com/trycua/) project to collaborate together.

