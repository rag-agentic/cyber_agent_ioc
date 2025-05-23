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


from cyber_agent_ioc.prompt import ThreatNetworkLogPrompts
from cyber_agent_ioc.utils import get_live_network_traffic

logger = logging.getLogger(__name__)

# Module level variable to track empty query handling
_empty_query_handled = False

class NetworkLogToolConfig(FunctionBaseConfig, name="network_log_tool"):
    """
    Tool that retrieves the lastest log from the MACOS VM.
    Requires a the param (time last x minute )
    """
    description: str = Field(
        default=("This Tool that retrieves the network traffic from the MACOS VM, "
                 "Requires a the param interface, number of capture and  timeout "),
        description="Description of the tool for the agent.")
    llm_name: LLMRef
    interface: str = Field(
        default="en0",
        description="The network interface used to dump traffic.")
    ct_packet: int | None = Field(None,
                       description="The number of capture for the netxotk traffic")             
    timeout: int | None = Field(
        None,
        description="The number of seconds to wait before returning data, ensuring all relevant events are captured."
    )
    pass
 
@register_function(config_type=NetworkLogToolConfig, framework_wrappers=[LLMFrameworkEnum.LANGCHAIN])
async def network_log_tool(config:NetworkLogToolConfig, builder: Builder):
    """
    Create a get log process tool for use with langchain.

    This creates a retrieve function that get process from MACOS VM System.

    Parameters
    ----------
    tool_config : network_log_tool
        Configuration for the process log Config
    builder : Builder
        The AIQ Toolkit builder instance

    Returns
    -------
    A FunctionInfo object wrapping the process log 
    """
    async def _arun(last_time: int) -> str:
  
        # Additional LLM reasoning layer on playbook output to provide a summary of the results
        logger.info("LLM network traffic log Reasoning")
        try:
            # Get the language model
            llm = await builder.get_llm(config.llm_name, wrapper_type=LLMFrameworkEnum.LANGCHAIN)
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            #CAll the tool for get system log 
            network_traffic = await get_live_network_traffic(config.interface,config.ct_packet, config.timeout)
            logger.info(network_traffic)

            output_for_prompt = f"Here the network traffic captured at {current_time}. Here the log: {network_traffic}"

            user_prompt = ThreatNetworkLogPrompts.USER_INSTRUCTIONS_PROMPT.format(input_data=output_for_prompt)

            prompt = ChatPromptTemplate([SystemMessage(content=ThreatNetworkLogPrompts.SYSTEM_INSTRUCTIONS_PROMPT),
                                        MessagesPlaceholder("msgs")])
        
            chain = prompt | llm
            result = await chain.ainvoke({"msgs": [HumanMessage(content=user_prompt)]})
            logger.info(result.content)

            return result.content
        except Exception as e:
            logger.error(f"Error in network traffic agent: {str(e)}")
            return f"Sorry, I encountered an error while generating your analyst network traffic: {str(e)}"
 
    yield FunctionInfo.from_fn(
        _arun,
        description=config.description,
    )
