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

import logging
import os

from datetime import datetime

from pydantic import Field, BaseModel, conint
from textwrap import dedent

from aiq.builder.builder import Builder
from aiq.builder.framework_enum import LLMFrameworkEnum
from aiq.builder.function_info import FunctionInfo
from aiq.cli.register_workflow import register_function
from aiq.data_models.component_ref import FunctionRef
from aiq.data_models.function import FunctionBaseConfig
from aiq.data_models.component_ref import LLMRef

from langchain_core.messages import HumanMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.prompts import MessagesPlaceholder
from langchain_core.messages import SystemMessage, HumanMessage
import requests

logger = logging.getLogger(__name__)

class IpCompromiseCheckTool(FunctionBaseConfig, name="ip_compromise_tool"):
    """
    Tool that retrieves the lastest log from the MACOS VM.
    Requires a the param (time last x minute )
    """
    description: str = Field(
        default=("This Tool that retrieves the network traffic from the MACOS VM, "
                 "Requires a the param interface, number of capture and  timeout "),
        description="Description of the tool for the agent.")
    llm_name: LLMRef
    api_key : str = Field(default=("XXXX"))
    url: str = Field(
        default="url",
        description="Url to check if an IP is compromised")
    pass

@register_function(config_type=IpCompromiseCheckTool, framework_wrappers=[LLMFrameworkEnum.LANGCHAIN])
async def ip_compromise_tool(config:IpCompromiseCheckTool, builder: Builder):
    """
    Create a get log compromised ip check for use with langchain.

    This creates a retrieve function that return if IP found on MACOS VM System is compromised.

    Parameters
    ----------
    tool_config : ip_compromise_tool
         
    builder : Builder
        The AIQ Toolkit builder instance

    Returns
    -------
    A FunctionInfo object wrapping the result of compromised IP
    """
    async def _arun(ip_adress: str) -> str:
        # Additional LLM reasoning layer on playbook output to provide a summary of the results
        logger.info("LLM network traffic log Reasoning")
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
            headers = {"Key": config.api_key, "Accept": "application/json"}
            response = requests.get(url, headers=headers)
            data = response.json()
            # Extraire l'URL ou l'info pertinente
            return data
        except Exception as e:
            logger.error(f"Error in network traffic agent: {str(e)}")
            return f"Sorry, I encountered an error while generating your analyst network traffic: {str(e)}"
 
    yield FunctionInfo.from_fn(
        _arun,
        description=config.description,
    )