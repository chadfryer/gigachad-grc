# AI Configuration

Configure AI-powered features in GigaChad GRC using OpenAI or Anthropic providers.

## Overview

GigaChad GRC integrates with leading AI providers to deliver intelligent GRC capabilities:

- **Risk Scoring**: AI-suggested likelihood and impact ratings with detailed rationale
- **Auto-Categorization**: Automatic categorization and tagging of controls, risks, and policies
- **Smart Search**: Natural language search across all GRC modules
- **Policy Drafting**: Generate policy drafts based on requirements and templates
- **Control Suggestions**: AI-recommended controls for risks and compliance requirements

## Supported AI Providers

### OpenAI

| Model | Identifier | Best For |
|-------|------------|----------|
| GPT-5 (Most Capable) | `gpt-5` | Complex analysis, policy drafting |
| GPT-5 Mini | `gpt-5-mini` | Faster responses, cost-effective |
| o3 (Advanced Reasoning) | `o3` | Complex risk scenarios |
| o3-mini | `o3-mini` | Quick reasoning tasks |

### Anthropic

| Model | Identifier | Best For |
|-------|------------|----------|
| Claude Opus 4.5 (Most Capable) | `claude-opus-4.5` | Comprehensive analysis |
| Claude Sonnet 4 | `claude-sonnet-4` | Balanced capability/speed |
| Claude 3.5 Sonnet | `claude-3-5-sonnet` | General purpose |
| Claude 3.5 Haiku | `claude-3-5-haiku` | Fast responses |

## Configuration Steps

### 1. Access AI Settings

Navigate to **Settings → AI Configuration**

### 2. Select Provider

Choose your preferred AI provider:

1. Click the provider card (OpenAI or Anthropic)
2. Provider selection affects available models

### 3. Enter API Key

1. Obtain your API key:
   - **OpenAI**: https://platform.openai.com/api-keys
   - **Anthropic**: https://console.anthropic.com/settings/keys

2. Enter the API key in the secure input field

3. Click **Verify** to test the connection

> ⚠️ **Security Note**: API keys are encrypted at rest and never exposed in logs or the UI after saving.

### 4. Select Model

Choose the model based on your needs:

- **Most Capable**: Best quality, higher cost, slower
- **Balanced**: Good quality, moderate cost, reasonable speed
- **Fast**: Quick responses, lower cost, simpler tasks

### 5. Enable Features

Toggle individual AI features:

| Feature | Description |
|---------|-------------|
| **Risk Scoring** | AI suggests likelihood/impact ratings |
| **Auto-Categorization** | Automatic tagging and categorization |
| **Smart Search** | Natural language search queries |
| **Policy Drafting** | AI-generated policy content |
| **Control Suggestions** | Recommended controls for risks |

### 6. Save Configuration

Click **Save Configuration** to apply settings.

## Using AI Features

### Risk Scoring

When creating or editing a risk:

1. Enter the risk description
2. Click **Get AI Suggestion**
3. Review the suggested scores and rationale
4. Accept, modify, or dismiss

**Request Body:**
```json
{
  "riskId": "risk-uuid",
  "description": "Detailed risk description...",
  "context": {
    "category": "Cybersecurity",
    "existingControls": ["Control 1", "Control 2"]
  }
}
```

**Response:**
```json
{
  "likelihood": 3,
  "impact": 4,
  "inherentRisk": 12,
  "rationale": "Based on the described threat vector...",
  "confidence": 0.85
}
```

### Auto-Categorization

Automatically categorize items:

1. Create a new control, risk, or policy
2. AI suggests categories based on content
3. Review and confirm suggestions

### Smart Search

Use natural language to search:

- "Show all high risks in the data privacy category"
- "Find controls related to access management"
- "List policies expiring this quarter"

### Policy Drafting

Generate policy drafts:

1. Navigate to **Policies → Create New**
2. Select **AI Draft** option
3. Provide context:
   - Policy type
   - Applicable frameworks
   - Key requirements
4. Review and edit the generated draft

### Control Suggestions

Get AI-recommended controls:

1. Open a risk or requirement
2. Click **Suggest Controls**
3. AI analyzes and recommends controls
4. Link suggested controls to the item

## API Reference

### Get AI Configuration

```http
GET /api/ai/config
```

Returns current AI configuration status (without exposing the API key).

### Risk Scoring

```http
POST /api/ai/risk-scoring
Content-Type: application/json

{
  "riskId": "string",
  "description": "string",
  "context": {
    "category": "string",
    "existingControls": ["string"]
  }
}
```

### Auto-Categorization

```http
POST /api/ai/categorize
Content-Type: application/json

{
  "entityType": "risk" | "control" | "policy",
  "content": "string",
  "existingCategories": ["string"]
}
```

### Smart Search

```http
POST /api/ai/search
Content-Type: application/json

{
  "query": "natural language search query",
  "modules": ["risks", "controls", "policies"],
  "limit": 20
}
```

### Policy Drafting

```http
POST /api/ai/policy-draft
Content-Type: application/json

{
  "policyType": "string",
  "requirements": ["string"],
  "frameworks": ["SOC2", "ISO27001"],
  "context": "Additional context..."
}
```

### Control Suggestions

```http
POST /api/ai/control-suggestions
Content-Type: application/json

{
  "riskId": "string",
  "requirementId": "string",
  "existingControls": ["string"]
}
```

## Demo Mode

GigaChad GRC's AI features can operate in **demo mode** when no AI provider is configured. This allows you to explore the AI capabilities before obtaining API keys.

### How Demo Mode Works

When AI is not configured:

1. **Sample Responses**: AI endpoints return realistic sample recommendations
2. **Mock Flag**: API responses include `isMockMode: true`
3. **UI Indication**: The interface shows "AI running in demo mode"
4. **No API Calls**: No requests are made to external AI providers

### Demo Response Example

```json
{
  "likelihood": 3,
  "impact": 4,
  "inherentRisk": 12,
  "rationale": "This is a sample AI recommendation. Configure an AI provider for actual analysis.",
  "confidence": 0.0,
  "isMockMode": true,
  "mockModeReason": "AI provider not configured - set OPENAI_API_KEY or ANTHROPIC_API_KEY"
}
```

### Transitioning to Production

To enable real AI analysis:

1. **Obtain API Key**: Get a key from OpenAI or Anthropic
2. **Configure Provider**: Set the environment variable or use the Settings UI
3. **Test Connection**: Verify the API key works
4. **Enable Features**: Toggle on the AI features you want

### Environment Variables

Configure AI via environment variables:

```bash
# OpenAI
OPENAI_API_KEY=sk-xxxxxx
OPENAI_MODEL=gpt-4

# Or Anthropic
ANTHROPIC_API_KEY=sk-ant-xxxxxx
ANTHROPIC_MODEL=claude-sonnet-4

# Enable AI features
ENABLE_AI_FEATURES=true
```

## Best Practices

### API Key Security

- Store API keys in secure environment variables
- Rotate keys periodically
- Use separate keys for development and production
- Monitor API usage for anomalies

### Cost Management

- Start with smaller/faster models
- Use specific queries rather than broad ones
- Implement caching for repeated queries
- Set usage limits in provider dashboards

### Quality Improvement

- Provide detailed context in requests
- Review and correct AI suggestions
- Maintain consistent terminology
- Update configuration as new models become available

## Troubleshooting

### API Connection Failed

1. Verify API key is correct
2. Check provider service status
3. Ensure network allows outbound HTTPS
4. Verify key has appropriate permissions

### Slow Responses

1. Consider using a faster model
2. Reduce context size in requests
3. Check provider rate limits
4. Implement request timeouts

### Inaccurate Suggestions

1. Provide more detailed context
2. Use a more capable model
3. Review and update category definitions
4. Submit feedback on suggestions

## Related Topics

- [AI Risk Assistant](risk-assistant.md)
- [MCP Server Integration](../mcp-quick-start.md)
- [Risk Management](../risk-management/dashboard.md)
