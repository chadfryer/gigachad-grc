import { DefaultAzureCredential } from '@azure/identity';
import { ResourceManagementClient } from '@azure/arm-resources';

interface AzureEvidenceParams {
  subscriptionId: string;
  resourceTypes?: string[];
}

interface EvidenceResult {
  service: string;
  collectedAt: string;
  subscriptionId: string;
  findings: unknown[];
  summary: {
    totalResources: number;
    compliantResources: number;
    nonCompliantResources: number;
  };
  isMockMode?: boolean;
  mockModeReason?: string;
  requiredCredentials?: string[];
}

export async function collectAzureEvidence(params: AzureEvidenceParams): Promise<EvidenceResult> {
  const { subscriptionId, resourceTypes = ['security-center', 'key-vault', 'network', 'storage'] } = params;
  const findings: unknown[] = [];
  let compliantCount = 0;
  let nonCompliantCount = 0;

  try {
    const credential = new DefaultAzureCredential();
    const resourceClient = new ResourceManagementClient(credential, subscriptionId);

    // Collect resource groups
    const resourceGroups: unknown[] = [];
    for await (const rg of resourceClient.resourceGroups.list()) {
      resourceGroups.push({
        name: rg.name,
        location: rg.location,
        tags: rg.tags,
        provisioningState: rg.properties?.provisioningState,
      });
    }

    findings.push({
      type: 'resource_groups',
      count: resourceGroups.length,
      groups: resourceGroups,
    });

    // Collect resources by type
    for (const resourceType of resourceTypes) {
      try {
        switch (resourceType.toLowerCase()) {
          case 'security-center':
            findings.push(await collectSecurityCenterEvidence(subscriptionId));
            break;
          case 'key-vault':
            findings.push(await collectKeyVaultEvidence(resourceClient));
            break;
          case 'network':
            findings.push(await collectNetworkEvidence(resourceClient));
            break;
          case 'storage':
            findings.push(await collectStorageEvidence(resourceClient));
            break;
          default:
            findings.push({
              type: resourceType,
              error: `Unsupported resource type: ${resourceType}`,
            });
        }
      } catch (error) {
        findings.push({
          type: resourceType,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        nonCompliantCount++;
      }
    }

    // Calculate totals
    const resourceCount = findings.reduce<number>((total: number, f) => {
      const finding = f as Record<string, unknown>;
      if (typeof finding.count === 'number') {
        return total + finding.count;
      }
      return total;
    }, 0);

    return {
      service: 'azure',
      collectedAt: new Date().toISOString(),
      subscriptionId,
      findings,
      summary: {
        totalResources: resourceCount,
        compliantResources: compliantCount,
        nonCompliantResources: nonCompliantCount,
      },
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const isAuthError = errorMessage.includes('credential') || 
                        errorMessage.includes('authentication') ||
                        errorMessage.includes('AZURE_');
    
    console.warn(`Azure evidence collection failed: ${errorMessage}`);
    
    return {
      service: 'azure',
      collectedAt: new Date().toISOString(),
      subscriptionId,
      findings: [],
      summary: {
        totalResources: 0,
        compliantResources: 0,
        nonCompliantResources: 0,
      },
      isMockMode: true,
      mockModeReason: isAuthError 
        ? 'Azure credentials not configured. Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID environment variables, or run on Azure with managed identity.'
        : `Azure evidence collection failed: ${errorMessage}`,
      requiredCredentials: isAuthError 
        ? ['AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID'] 
        : undefined,
    };
  }
}

async function collectSecurityCenterEvidence(subscriptionId: string): Promise<unknown> {
  try {
    // Try to use the Azure Security SDK with require() for runtime loading
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { SecurityCenter } = require('@azure/arm-security');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { DefaultAzureCredential } = require('@azure/identity');
    
    const credential = new DefaultAzureCredential();
    const client = new SecurityCenter(credential, subscriptionId);
    
    // Collect secure score
    const secureScores: unknown[] = [];
    for await (const score of client.secureScores.list()) {
      secureScores.push({
        name: score.displayName,
        current: score.current,
        max: score.max,
        percentage: score.percentage,
      });
    }
    
    // Collect recommendations
    const recommendations: unknown[] = [];
    for await (const rec of client.recommendations.list()) {
      recommendations.push({
        name: rec.displayName,
        status: rec.status,
        resourceId: rec.resourceDetails?.source,
      });
    }
    
    return {
      type: 'security_center',
      subscriptionId,
      collectedAt: new Date().toISOString(),
      findings: {
        secureScores,
        recommendations: recommendations.slice(0, 50), // Limit for storage
        recommendationCount: recommendations.length,
      },
    };
  } catch (error: any) {
    // SDK not available or error occurred
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const isModuleError = error.code === 'MODULE_NOT_FOUND' || 
                          errorMessage.includes('Cannot find module');
    
    console.warn(`Security Center evidence collection: ${isModuleError ? 'SDK not installed' : errorMessage}`);
    
    return {
      type: 'security_center',
      subscriptionId,
      collectedAt: new Date().toISOString(),
      findings: {
        secureScore: { current: 0, max: 100, percentage: 0 },
        recommendations: [],
        alerts: [],
      },
      isMockMode: true,
      mockModeReason: isModuleError 
        ? 'Install @azure/arm-security SDK for actual Security Center data'
        : `Security Center collection failed: ${errorMessage}`,
    };
  }
}

async function collectKeyVaultEvidence(resourceClient: ResourceManagementClient): Promise<unknown> {
  const keyVaults: unknown[] = [];

  // List all Key Vault resources
  for await (const resource of resourceClient.resources.list({
    filter: "resourceType eq 'Microsoft.KeyVault/vaults'",
  })) {
    keyVaults.push({
      name: resource.name,
      location: resource.location,
      id: resource.id,
      tags: resource.tags,
      sku: resource.sku,
    });
  }

  return {
    type: 'key_vault',
    count: keyVaults.length,
    vaults: keyVaults,
    compliance: {
      // In a real implementation, you would check:
      // - Soft delete enabled
      // - Purge protection enabled
      // - Network rules configured
      // - Access policies properly configured
      note: 'Detailed Key Vault compliance checks require additional API calls',
    },
  };
}

async function collectNetworkEvidence(resourceClient: ResourceManagementClient): Promise<unknown> {
  const networkResources: Record<string, unknown[]> = {
    virtualNetworks: [],
    networkSecurityGroups: [],
    publicIpAddresses: [],
  };

  // List Virtual Networks
  for await (const resource of resourceClient.resources.list({
    filter: "resourceType eq 'Microsoft.Network/virtualNetworks'",
  })) {
    networkResources.virtualNetworks.push({
      name: resource.name,
      location: resource.location,
      id: resource.id,
    });
  }

  // List Network Security Groups
  for await (const resource of resourceClient.resources.list({
    filter: "resourceType eq 'Microsoft.Network/networkSecurityGroups'",
  })) {
    networkResources.networkSecurityGroups.push({
      name: resource.name,
      location: resource.location,
      id: resource.id,
    });
  }

  // List Public IP Addresses
  for await (const resource of resourceClient.resources.list({
    filter: "resourceType eq 'Microsoft.Network/publicIPAddresses'",
  })) {
    networkResources.publicIpAddresses.push({
      name: resource.name,
      location: resource.location,
      id: resource.id,
    });
  }

  return {
    type: 'network',
    count:
      networkResources.virtualNetworks.length +
      networkResources.networkSecurityGroups.length +
      networkResources.publicIpAddresses.length,
    resources: networkResources,
    compliance: {
      note: 'Detailed network compliance checks require examining NSG rules, VNet peering, etc.',
    },
  };
}

async function collectStorageEvidence(resourceClient: ResourceManagementClient): Promise<unknown> {
  const storageAccounts: unknown[] = [];

  // List Storage Accounts
  for await (const resource of resourceClient.resources.list({
    filter: "resourceType eq 'Microsoft.Storage/storageAccounts'",
  })) {
    storageAccounts.push({
      name: resource.name,
      location: resource.location,
      id: resource.id,
      sku: resource.sku,
      kind: resource.kind,
    });
  }

  return {
    type: 'storage',
    count: storageAccounts.length,
    accounts: storageAccounts,
    compliance: {
      // In a real implementation, you would check:
      // - HTTPS only
      // - Encryption at rest
      // - Public blob access disabled
      // - Network rules configured
      note: 'Detailed storage compliance checks require @azure/arm-storage SDK',
    },
  };
}

