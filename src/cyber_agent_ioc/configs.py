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

