export CUA_TELEMETRY_ENABLED=off
uv pip install  .
aiq validate --config_file  src/cyber_agent_ioc/configs/config.yml

