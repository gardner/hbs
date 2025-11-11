#!/usr/bin/env bash

set -a && source .env && set +a

#claude mcp add --transport http context7 https://mcp.context7.com/mcp --header "CONTEXT7_API_KEY: ctx7sk-166a1605-dddb-4e4b-beb0-79d98a9232c2"

pnpm dlx @anthropic-ai/claude-code@latest "$@"
