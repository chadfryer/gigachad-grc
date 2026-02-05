import {
  BaseAIProvider,
  AIMessage,
  AICompletionOptions,
  AICompletionResult,
  AIProviderConfig,
} from './ai-provider.interface';
import {
  POLICY_TEMPLATES,
  getPolicyTemplate,
  getAvailablePolicyTypes,
  generatePolicyContent,
  replacePlaceholders,
} from '../templates/policy-templates';

/**
 * Mock AI Provider Implementation
 *
 * Provides template-based responses for testing AI features without an API key.
 * Useful for:
 * - Development and testing
 * - Demonstrations and stakeholder previews
 * - Environments without AI API access
 *
 * The mock provider returns realistic, structured responses based on templates.
 */
export class MockAIProvider extends BaseAIProvider {
  readonly name = 'mock';

  private static readonly AVAILABLE_MODELS = ['mock-gpt-4', 'mock-claude', 'mock-fast'];

  constructor(config?: Partial<AIProviderConfig>) {
    super({
      apiKey: 'mock-api-key',
      defaultModel: 'mock-gpt-4',
      defaultTemperature: 0.7,
      defaultMaxTokens: 4096,
      baseUrl: '',
      timeout: 1000,
      ...config,
    });
  }

  /**
   * Mock provider is always configured and ready
   */
  isConfigured(): boolean {
    return true;
  }

  getAvailableModels(): string[] {
    return [...MockAIProvider.AVAILABLE_MODELS];
  }

  isValidModel(model: string): boolean {
    return MockAIProvider.AVAILABLE_MODELS.includes(model) || model.startsWith('mock-');
  }

  /**
   * Generate a completion by analyzing the prompt and returning appropriate mock responses
   */
  async complete(
    messages: AIMessage[],
    options?: Partial<AICompletionOptions>
  ): Promise<AICompletionResult> {
    // Simulate network delay (50-200ms)
    await this.simulateDelay();

    const effectiveOptions = this.getEffectiveOptions(options);
    const prompt = messages.map((m) => m.content).join('\n');

    // Detect the type of request and generate appropriate response
    const response = this.generateMockResponse(prompt, effectiveOptions);

    return {
      content: response,
      model: `${effectiveOptions.model} (mock)`,
      tokensUsed: {
        prompt: this.estimateTokens(prompt),
        completion: this.estimateTokens(response),
        total: this.estimateTokens(prompt) + this.estimateTokens(response),
      },
      finishReason: 'stop',
    };
  }

  /**
   * Simulate network delay for realistic behavior
   */
  private async simulateDelay(): Promise<void> {
    const delay = Math.random() * 150 + 50; // 50-200ms
    await new Promise((resolve) => setTimeout(resolve, delay));
  }

  /**
   * Estimate token count (rough approximation)
   */
  private estimateTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  /**
   * Generate appropriate mock response based on prompt content
   */
  private generateMockResponse(prompt: string, _options: AICompletionOptions): string {
    const promptLower = prompt.toLowerCase();

    // Policy drafting
    if (
      promptLower.includes('policy') &&
      (promptLower.includes('draft') ||
        promptLower.includes('create') ||
        promptLower.includes('generate'))
    ) {
      return this.generatePolicyDraftResponse(prompt);
    }

    // Risk scoring
    if (
      promptLower.includes('risk') &&
      (promptLower.includes('analyze') ||
        promptLower.includes('score') ||
        promptLower.includes('assess'))
    ) {
      return this.generateRiskScoringResponse(prompt);
    }

    // Categorization
    if (promptLower.includes('categorize') || promptLower.includes('categorization')) {
      return this.generateCategorizationResponse(prompt);
    }

    // Control suggestions
    if (
      promptLower.includes('control') &&
      (promptLower.includes('suggest') || promptLower.includes('recommend'))
    ) {
      return this.generateControlSuggestionsResponse(prompt);
    }

    // Smart search
    if (promptLower.includes('search') || promptLower.includes('find')) {
      return this.generateSearchResponse(prompt);
    }

    // Default response
    return this.generateGenericResponse(prompt);
  }

  /**
   * Generate mock policy draft response
   */
  private generatePolicyDraftResponse(prompt: string): string {
    // Extract policy type and organization name from prompt
    const policyTypeMatch = prompt.match(
      /(?:draft|create|generate)\s+(?:a\s+)?([^.]+?)(?:\s+for|\s+policy)/i
    );
    const orgMatch = prompt.match(/(?:for|organization[:\s]+)([^.\n]+)/i);
    const frameworksMatch = prompt.match(/frameworks?(?:\s+to\s+address)?[:\s]+([^.\n]+)/i);
    const industryMatch = prompt.match(/industry[:\s]+([^.\n]+)/i);

    const policyType = policyTypeMatch?.[1]?.trim() || 'Information Security Policy';
    const organizationName = orgMatch?.[1]?.trim() || 'Acme Corporation';
    const frameworksStr = frameworksMatch?.[1]?.trim() || '';
    const industry = industryMatch?.[1]?.trim();

    // Parse frameworks
    const frameworks = frameworksStr
      .split(/[,\s]+/)
      .filter((f) => f.length > 2)
      .map((f) => f.trim());

    // Find matching template
    let template = getPolicyTemplate(policyType);
    if (!template) {
      // Default to Information Security Policy
      template = POLICY_TEMPLATES[0];
    }

    // Generate full content
    const fullContent = generatePolicyContent(template, organizationName, frameworks, industry);

    // Build response JSON
    const response = {
      title: replacePlaceholders(template.title, organizationName, industry),
      content: fullContent,
      sections: template.sections.map((s) => ({
        title: replacePlaceholders(s.title, organizationName, industry),
        content: replacePlaceholders(s.content, organizationName, industry),
        order: s.order,
      })),
      frameworksCovered:
        frameworks.length > 0 ? frameworks : Object.keys(template.frameworkMappings),
      suggestedReviewSchedule: template.suggestedReviewSchedule,
      relatedPolicies: template.relatedPolicies,
    };

    return JSON.stringify(response, null, 2);
  }

  /**
   * Generate mock risk scoring response
   */
  private generateRiskScoringResponse(prompt: string): string {
    // Extract risk details from prompt
    const titleMatch = prompt.match(/title[:\s]+([^\n]+)/i);
    const descMatch = prompt.match(/description[:\s]+([^\n]+)/i);

    const riskTitle = titleMatch?.[1]?.trim() || 'Unspecified Risk';
    const _description = descMatch?.[1]?.trim() || '';

    // Generate contextual scores based on keywords
    let likelihood = 3;
    let impact = 3;
    let category = 'Operational';

    const promptLower = prompt.toLowerCase();

    // Adjust scores based on keywords
    if (
      promptLower.includes('data breach') ||
      promptLower.includes('ransomware') ||
      promptLower.includes('critical')
    ) {
      likelihood = 4;
      impact = 5;
      category = 'Security';
    } else if (promptLower.includes('compliance') || promptLower.includes('regulatory')) {
      likelihood = 3;
      impact = 4;
      category = 'Compliance';
    } else if (promptLower.includes('vendor') || promptLower.includes('third-party')) {
      likelihood = 3;
      impact = 3;
      category = 'Third-Party';
    } else if (promptLower.includes('availability') || promptLower.includes('downtime')) {
      likelihood = 3;
      impact = 4;
      category = 'Operational';
    }

    const riskScore = likelihood * impact;
    let riskLevel: string;
    if (riskScore <= 4) riskLevel = 'Low';
    else if (riskScore <= 9) riskLevel = 'Medium';
    else if (riskScore <= 16) riskLevel = 'High';
    else riskLevel = 'Critical';

    const response = {
      likelihood,
      impact,
      riskScore,
      riskLevel,
      likelihoodRationale: `Based on industry trends and the nature of "${riskTitle}", the likelihood of occurrence is assessed as ${likelihood}/5. Organizations in similar sectors have experienced comparable incidents with moderate frequency.`,
      impactRationale: `If realized, this risk could result in ${impact >= 4 ? 'significant' : 'moderate'} business disruption, potential regulatory penalties, and reputational damage. The impact score of ${impact}/5 reflects these potential consequences.`,
      suggestedCategory: category,
      recommendedControls: [
        'Implement monitoring and detection capabilities',
        'Establish incident response procedures',
        'Conduct regular risk assessments',
        'Deploy preventive technical controls',
        'Provide security awareness training',
      ],
      confidence: 75,
    };

    return JSON.stringify(response, null, 2);
  }

  /**
   * Generate mock categorization response
   */
  private generateCategorizationResponse(prompt: string): string {
    const titleMatch = prompt.match(/title[:\s]+([^\n]+)/i);
    const entityTypeMatch = prompt.match(/(?:categorize|the following)\s+(\w+)/i);

    const title = titleMatch?.[1]?.trim() || 'Unnamed Entity';
    const entityType = entityTypeMatch?.[1]?.toLowerCase() || 'control';

    let primaryCategory: string;
    let subcategory: string;
    const tags: string[] = [];
    const relatedFrameworks: string[] = [];

    const promptLower = prompt.toLowerCase();

    // Determine categories based on keywords
    if (promptLower.includes('access') || promptLower.includes('authentication')) {
      primaryCategory = 'Access Control';
      subcategory = 'Authentication & Authorization';
      tags.push('access-management', 'authentication', 'identity');
      relatedFrameworks.push('SOC 2 CC6.1', 'ISO 27001 A.5.15');
    } else if (promptLower.includes('encrypt') || promptLower.includes('crypto')) {
      primaryCategory = 'Cryptography';
      subcategory = 'Data Encryption';
      tags.push('encryption', 'cryptography', 'data-protection');
      relatedFrameworks.push('SOC 2 CC6.1', 'ISO 27001 A.8.24');
    } else if (promptLower.includes('incident') || promptLower.includes('response')) {
      primaryCategory = 'Incident Management';
      subcategory = 'Response Procedures';
      tags.push('incident-response', 'security-operations');
      relatedFrameworks.push('SOC 2 CC7.4', 'ISO 27001 A.5.26');
    } else if (promptLower.includes('backup') || promptLower.includes('recovery')) {
      primaryCategory = 'Business Continuity';
      subcategory = 'Backup & Recovery';
      tags.push('backup', 'disaster-recovery', 'availability');
      relatedFrameworks.push('SOC 2 A1.2', 'ISO 27001 A.8.13');
    } else if (promptLower.includes('vendor') || promptLower.includes('third-party')) {
      primaryCategory = 'Supplier Relationships';
      subcategory = 'Third-Party Management';
      tags.push('vendor-management', 'supply-chain');
      relatedFrameworks.push('SOC 2 CC9.2', 'ISO 27001 A.5.19');
    } else {
      primaryCategory = 'Information Security';
      subcategory = 'General Controls';
      tags.push('security', 'compliance');
      relatedFrameworks.push('SOC 2 CC1.1', 'ISO 27001 A.5.1');
    }

    const response = {
      primaryCategory,
      subcategory,
      tags,
      relatedFrameworks,
      confidence: 80,
      explanation: `Based on the analysis of "${title}", this ${entityType} has been categorized under ${primaryCategory} with subcategory ${subcategory}. This categorization aligns with common GRC taxonomy and framework mappings.`,
    };

    return JSON.stringify(response, null, 2);
  }

  /**
   * Generate mock control suggestions response
   */
  private generateControlSuggestionsResponse(_prompt: string): string {
    const controls = [
      {
        title: 'Access Control Management',
        description: 'Implement role-based access control (RBAC) with principle of least privilege',
        category: 'Access Control',
        implementationGuidance:
          'Define roles and permissions matrix. Implement access provisioning workflows. Enable access reviews.',
        effortEstimate: 'Medium',
        effectivenessRating: 5,
        frameworkMappings: ['SOC 2 CC6.1', 'ISO 27001 A.5.15', 'NIST CSF PR.AC-1'],
        priority: 1,
      },
      {
        title: 'Security Monitoring and Logging',
        description: 'Establish centralized logging and security monitoring capabilities',
        category: 'Operations Security',
        implementationGuidance:
          'Deploy SIEM solution. Configure log collection from critical systems. Create alerting rules.',
        effortEstimate: 'High',
        effectivenessRating: 5,
        frameworkMappings: ['SOC 2 CC7.2', 'ISO 27001 A.8.15', 'NIST CSF DE.CM-1'],
        priority: 2,
      },
      {
        title: 'Vulnerability Management',
        description: 'Regular vulnerability scanning and remediation process',
        category: 'Operations Security',
        implementationGuidance:
          'Implement vulnerability scanning tools. Establish patching cadence. Track remediation metrics.',
        effortEstimate: 'Medium',
        effectivenessRating: 4,
        frameworkMappings: ['SOC 2 CC7.1', 'ISO 27001 A.8.8', 'NIST CSF ID.RA-1'],
        priority: 3,
      },
      {
        title: 'Data Encryption',
        description: 'Encrypt sensitive data at rest and in transit',
        category: 'Cryptography',
        implementationGuidance:
          'Enable TLS 1.2+ for transit. Implement AES-256 for data at rest. Manage encryption keys securely.',
        effortEstimate: 'Medium',
        effectivenessRating: 5,
        frameworkMappings: ['SOC 2 CC6.1', 'ISO 27001 A.8.24', 'PCI DSS 3.4'],
        priority: 4,
      },
      {
        title: 'Security Awareness Training',
        description: 'Regular security training and phishing simulations for all employees',
        category: 'Human Resources Security',
        implementationGuidance:
          'Implement training platform. Create role-based training paths. Track completion rates.',
        effortEstimate: 'Low',
        effectivenessRating: 4,
        frameworkMappings: ['SOC 2 CC1.4', 'ISO 27001 A.6.3', 'NIST CSF PR.AT-1'],
        priority: 5,
      },
    ];

    const response = {
      controls,
      gapAnalysis:
        'Based on the provided context, the organization would benefit from strengthening access controls, implementing comprehensive monitoring, and establishing a vulnerability management program. These foundational controls address common compliance requirements across SOC 2, ISO 27001, and other frameworks.',
      implementationRoadmap:
        'Phase 1 (0-3 months): Access Control and Encryption. Phase 2 (3-6 months): Security Monitoring and Logging. Phase 3 (6-9 months): Vulnerability Management and Training Program.',
      totalEffortEstimate: '6-9 months for full implementation with dedicated resources',
    };

    return JSON.stringify(response, null, 2);
  }

  /**
   * Generate mock search response
   */
  private generateSearchResponse(_prompt: string): string {
    const response = {
      results: [
        {
          entityType: 'control',
          id: 'mock-ctrl-001',
          title: 'Access Control Policy',
          relevance: 95,
          snippet: 'Manages user access rights and permissions...',
          explanation: 'Highly relevant based on search terms',
        },
        {
          entityType: 'policy',
          id: 'mock-pol-001',
          title: 'Information Security Policy',
          relevance: 85,
          snippet: 'Establishes security requirements...',
          explanation: 'Related to the search context',
        },
      ],
      interpretation: 'Searching for items related to the query terms',
      suggestedRefinements: ['Try narrowing by entity type', 'Add framework filter'],
      totalMatches: 2,
    };

    return JSON.stringify(response, null, 2);
  }

  /**
   * Generate generic response for unrecognized prompts
   */
  private generateGenericResponse(_prompt: string): string {
    return JSON.stringify(
      {
        message:
          'This is a mock AI response. The mock provider is active because no AI API key is configured.',
        suggestion:
          'To enable full AI capabilities, configure OPENAI_API_KEY or ANTHROPIC_API_KEY environment variables.',
        availablePolicyTypes: getAvailablePolicyTypes(),
        note: 'Mock responses are template-based and suitable for testing and demonstrations.',
      },
      null,
      2
    );
  }
}
