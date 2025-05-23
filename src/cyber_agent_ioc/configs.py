from dotenv import load_dotenv
import os

load_dotenv() 

#Global info
HOSTNAME = os.getenv('HOSTNAME')
USER = os.getenv('USER_VM')
SSH_KEY_PATH = os.getenv('SSH_KEY_PATH')

#Lume
URL_LUME_SDK = os.getenv('URL_LUME_SDK')
VM_NAME = os.getenv('VM_NAME')

#LOG
VM_PATH_LOG = os.getenv('VM_PATH_LOG')
LOCAL_PATH_LOG = os.getenv('LOCAL_PATH_LOG')

#PCAP
VM_PATH_PCAP = os.getenv('VM_PATH_PCAP')
LOCAL_PATH_PCAP = os.getenv('LOCAL_PATH_PCAP')

CONTEXT_WINDOWS = os.getenv('CONTEXT_WINDOWS')

