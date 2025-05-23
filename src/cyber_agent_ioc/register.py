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

# Import any tools which need to be automatically registered here
#from . import cyber_agent_ioc

import logging
from datetime import datetime

from pydantic import Field

from langchain_core.language_models.chat_models import BaseChatModel

from langchain_core.messages import HumanMessage
from langchain_core.messages import SystemMessage
from langchain_core.runnables import RunnableConfig

from aiq.builder.builder import Builder
from langgraph.graph import MessagesState
from langgraph.graph import StateGraph

from aiq.builder.framework_enum import LLMFrameworkEnum
from aiq.builder.function_info import FunctionInfo
from aiq.cli.register_workflow import register_function
from aiq.data_models.component_ref import LLMRef
from aiq.data_models.function import FunctionBaseConfig

from . import system_log_tool
from .prompt import ThreatHuntingPrompts
from .configs import VM_NAME
from .utils import check_vm_running
import sys

logger = logging.getLogger(__name__)

class CyberAgentIOCWorkflowConfig(FunctionBaseConfig, name="cyber_agent_ioc"):
    """
    Profiler agent config
    """
 
    llm_name: LLMRef = Field(..., description="The LLM to use for the profiler agent")
    max_iterations: int = Field(..., description="The maximum number of iterations for the profiler agent")
    tool_names: list[str] = Field(..., description="The tools to use for the profiler agent")
    max_retries: int = Field(
        ...,
        description="The maximum number of retries for the profiler agent",
    )

@register_function(config_type=CyberAgentIOCWorkflowConfig, framework_wrappers=[LLMFrameworkEnum.LANGCHAIN])
async def cyber_agent_ioc_workflow(config: CyberAgentIOCWorkflowConfig, builder: Builder):
    
    #Check here if the VM is running otherwise exit()
    if not check_vm_running(VM_NAME):
        logger.error("The VM is not running, please check with lume command : lume ls")
        sys.exit()

    llm: BaseChatModel = await builder.get_llm(config.llm_name, wrapper_type=LLMFrameworkEnum.LANGCHAIN)

    # Create the agent executor
    tool_names = builder.get_tools(tool_names=config.tool_names, wrapper_type=LLMFrameworkEnum.LANGCHAIN)
    #print(tool_names)
    #tools = []
    #for tool_name in tool_names:
    #    tool = builder.get_tool(tool_name, wrapper_type=LLMFrameworkEnum.LANGCHAIN)
    #    tools.append(tool)
    
    logger.info("builder.get_tool ok")

    """
    On lie les outils au modèle de langage, ce qui permet au LLM d’appeler ces outils pendant la génération de texte.
    parallel_tool_calls=True : le LLM pourra appeler plusieurs outils en parallèle si nécessaire.
    """
    llm_n_tools = llm.bind_tools(tool_names, parallel_tool_calls=True)
    
    # On récupère deux outils spécifiques  ici system_log_tool
    system_tool = builder.get_tool("system_log_tool", wrapper_type=LLMFrameworkEnum.LANGCHAIN)
    state = MessagesState(messages=[HumanMessage(content="Ma première alerte")])

    sys_msg = SystemMessage(content=ThreatHuntingPrompts.SYSTEM_DESCRIPTION_PROMPT)
    resultat = {"messages": [await llm_n_tools.ainvoke([sys_msg] + state["messages"])]}
    print("resulat", resultat)

    llm = await builder.get_llm(config.llm_name, wrapper_type=LLMFrameworkEnum.LANGCHAIN)

    async def _process_analyze_ioc(input_message: str) -> str:
        result = await system_tool._arun(3, config=RunnableConfig())
        return "OK"
    
    async def _response_fn(input_message: str) -> str:
        """Process alert message and return analysis with recommendations."""
        try:
            #result = await _process_alert(input_message)
            logger.info("Process workflow")
            result = await _process_analyze_ioc(input_message)
            return result
        finally:
            logger.info("Finished agent execution")      
    yield _response_fn