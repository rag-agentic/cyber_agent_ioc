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


from cyber_agent_ioc.prompt import ThreatSystemLogPrompts
from cyber_agent_ioc.utils import get_live_system_logs

logger = logging.getLogger(__name__)

#https://raw.githubusercontent.com/NVIDIA/AIQToolkit/refs/heads/develop/packages/aiqtoolkit_agno/src/aiq/plugins/agno/tools/serp_api_tool.py

# Module level variable to track empty query handling
_empty_query_handled = False

class SystemLogToolConfig(FunctionBaseConfig, name="system_log_tool"):
    """
    Tool that retrieves the lastest log from the MACOS VM.
    Requires a the param (time last x minute )
    """
    description: str = Field(
        default=("This Tool that retrieves the lastest log from the MACOS VM, "
                 "Requires a the param (time last x minute ) Args: last_time: str"),
        description="Description of the tool for the agent.")
    llm_name: LLMRef
    last_n: int | None = Field(
        None,
        description="The number of minutes to return. "
        "If user ask about the last run, then use 1",
    )
    pass
 
@register_function(config_type=SystemLogToolConfig, framework_wrappers=[LLMFrameworkEnum.LANGCHAIN])
async def system_log_tool(config:SystemLogToolConfig, builder: Builder):
    """
    Create a get log system tool for use with Agno.

    This creates a retrieve function that get log from MACOS VM System.

    Parameters
    ----------
    tool_config : system_log_tool
        Configuration for the Log System Config
    builder : Builder
        The AIQ Toolkit builder instance

    Returns
    -------
    A FunctionInfo object wrapping the log system 
    """
    async def _arun(last_time: int) -> str:
  
        # Additional LLM reasoning layer on playbook output to provide a summary of the results
        logger.info("LLM system Reasoning")
        try:
            # Get system log since last n minutes
            if not config.last_n:
                lasttime = 1
            lasttime = config.last_n
            #print("LAsttime = ",lasttime)
            # Get the language model
            llm = await builder.get_llm(config.llm_name, wrapper_type=LLMFrameworkEnum.LANGCHAIN)

            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            #CAll the tool for get system log 
            log_from_vm = await get_live_system_logs(lasttime)
            logger.info(log_from_vm)

            output_for_prompt = f"Here the system log retreived at {current_time}. Here the log: {log_from_vm}"

            user_prompt = ThreatSystemLogPrompts.USER_INSTRUCTIONS_PROMPT.format(input_data=output_for_prompt)

            #system_prompt = "Tu es un agent expert en analyse de texte."
            #user_prompt = "Combien de mots dans ce texte ?"

            #messages = ChatPromptTemplate([
            #    ("system", ThreatHuntingPrompts.PROMPT_SYSTEM_DESCRIPTION),
            #    ("user", ThreatHuntingPrompts.PROMPT_USER_INSTRUCTIONS)
            #])
            prompt = ChatPromptTemplate([SystemMessage(content=ThreatSystemLogPrompts.SYSTEM_DESCRIPTION_PROMPT),
                                        MessagesPlaceholder("msgs")])
        
            chain = prompt | llm
            result = await chain.ainvoke({"msgs": [HumanMessage(content=user_prompt)]})
            logger.info(result.content)

            return result.content
        except Exception as e:
            logger.error(f"Error in analyst log system agent: {str(e)}")
            return f"Sorry, I encountered an error while generating your analyst log system: {str(e)}"
 
    yield FunctionInfo.from_fn(
        _arun,
        description=config.description,
    )
