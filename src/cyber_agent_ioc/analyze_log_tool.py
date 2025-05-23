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


from .prompt import ThreatAnalystLogPrompts
 

logger = logging.getLogger(__name__)

# Module level variable to track empty query handling
_empty_query_handled = False

class AnalyzeToolConfig(FunctionBaseConfig, name="analyze_tool"):
    """
    Tool that retrieves the lastest log from the MACOS VM.
    Requires a the param (time last x minute )
    """
    description: str = Field(
        default=("This Tool analye all info from sub agent with tools (network, process, dns,system log) from the MACOS VM, "
                 "Requires a timeout "),
        description="Description of the global agent.")
    llm_name: LLMRef    
    pass
 
@register_function(config_type=AnalyzeToolConfig, framework_wrappers=[LLMFrameworkEnum.LANGCHAIN])
async def analyze_tool(config:AnalyzeToolConfig, builder: Builder):
    """
    Create a analyze tool for use with langchain.

    This creates a retrieve function that get process from MACOS VM System.

    Parameters
    ----------
    tool_config : analyze_tool
        Configuration for the analyze tool 
    builder : Builder
        The AIQ Toolkit builder instance

    Returns
    -------
    A FunctionInfo object wrapping the process log 
    """
    async def _arun(last_time: int) -> str:
  
        # Additional LLM reasoning layer on playbook output to provide a summary of the results
        logger.info("LLM global analyze Reasoning")
        try:
            # Get the language model
            llm = await builder.get_llm(config.llm_name, wrapper_type=LLMFrameworkEnum.LANGCHAIN)
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            user_prompt = ThreatAnalystLogPrompts.USER_INSTRUCTIONS_PROMPT.format(input_data="")

            prompt = ChatPromptTemplate([SystemMessage(content=ThreatAnalystLogPrompts.SYSTEM_INSTRUCTIONS_PROMPT),
                                        MessagesPlaceholder("msgs")])
        
            chain = prompt | llm
            result = await chain.ainvoke({"msgs": [HumanMessage(content=user_prompt)]})
            print("###########################@")
            logger.info(result.content)

            return result.content
        except Exception as e:
            logger.error(f"Error in analyze global agent: {str(e)}")
            return f"Sorry, I encountered an error while generating the analyst process : {str(e)}"
 
    yield FunctionInfo.from_fn(
        _arun,
        description=config.description,
    )

 

