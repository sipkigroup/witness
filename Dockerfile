# Dockerfile for the Glama MCP check (start over stdio, answer initialize + tools/list).
# deus-witness-mcp is a proxy: it needs an upstream MCP server after "--". For the check we put it in
# front of the bundled demo server (deus-witness-demo-tools: 4 tools, effects are only recorded to a file).
# The key below is a harmless placeholder so the proxy starts; real use: set DEUS_WITNESS_KEY (dwk_...)
# from https://witness.sipkigroup.com and replace the upstream command. Not for production.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEUS_WITNESS_HOME=/tmp/deus-witness \
    DEUS_DEMO_OUT=/tmp/deus-demo \
    DEUS_WITNESS_KEY=dwk_glama_introspection_placeholder
RUN pip install deus-witness==0.2.47
ENTRYPOINT ["deus-witness-mcp", "--", "deus-witness-demo-tools"]
