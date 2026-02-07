import { Injectable, Logger } from '@nestjs/common';
import { ConfigFormat } from '../dto/export-config.dto';
import { Exporter, ResourceData } from './exporter.interface';

@Injectable()
export class TerraformExporter implements Exporter {
  private readonly logger = new Logger(TerraformExporter.name);

  export(data: ResourceData, format: ConfigFormat): string {
    if (format !== ConfigFormat.TERRAFORM) {
      throw new Error(`Terraform exporter does not support format: ${format}`);
    }

    const startTime = Date.now();

    // Pre-allocate array with estimated size for better performance
    const estimatedSize =
      (data.controls?.length || 0) * 10 +
      (data.frameworks?.length || 0) * 8 +
      (data.policies?.length || 0) * 8 +
      (data.risks?.length || 0) * 10 +
      (data.vendors?.length || 0) * 8 +
      20; // Header

    const blocks: string[] = new Array(estimatedSize);
    let idx = 0;

    // Add provider block
    blocks[idx++] = 'terraform {';
    blocks[idx++] = '  required_providers {';
    blocks[idx++] = '    gigachad_grc = {';
    blocks[idx++] = '      source = "gigachad/grc"';
    blocks[idx++] = '    }';
    blocks[idx++] = '  }';
    blocks[idx++] = '}';
    blocks[idx++] = '';

    // Export controls
    if (data.controls && data.controls.length > 0) {
      blocks[idx++] = '# Controls';
      for (const control of data.controls) {
        blocks[idx++] =
          `resource "gigachad_grc_control" "${this.sanitizeName(control.controlId || control.id)}" {`;
        blocks[idx++] = `  control_id = "${control.controlId || control.id}"`;
        blocks[idx++] = `  title      = ${this.escapeString(control.title)}`;
        if (control.description) {
          blocks[idx++] = `  description = ${this.escapeString(control.description)}`;
        }
        if (control.category) {
          blocks[idx++] = `  category    = "${control.category}"`;
        }
        if (control.subcategory) {
          blocks[idx++] = `  subcategory = "${control.subcategory}"`;
        }
        if (control.tags && control.tags.length > 0) {
          blocks[idx++] = `  tags        = ${this.arrayToTerraform(control.tags)}`;
        }
        if (control.status) {
          blocks[idx++] = `  status      = "${control.status}"`;
        }
        blocks[idx++] = '}';
        blocks[idx++] = '';
      }
    }

    // Export frameworks
    if (data.frameworks && data.frameworks.length > 0) {
      blocks[idx++] = '# Frameworks';
      for (const framework of data.frameworks) {
        blocks[idx++] =
          `resource "gigachad_grc_framework" "${this.sanitizeName(framework.name)}" {`;
        blocks[idx++] = `  name        = ${this.escapeString(framework.name)}`;
        blocks[idx++] = `  type        = "${framework.type}"`;
        blocks[idx++] = `  version     = "${framework.version}"`;
        if (framework.description) {
          blocks[idx++] = `  description = ${this.escapeString(framework.description)}`;
        }
        blocks[idx++] = `  is_active   = ${framework.isActive}`;
        blocks[idx++] = '}';
        blocks[idx++] = '';
      }
    }

    // Export policies
    if (data.policies && data.policies.length > 0) {
      blocks[idx++] = '# Policies';
      for (const policy of data.policies) {
        blocks[idx++] = `resource "gigachad_grc_policy" "${this.sanitizeName(policy.title)}" {`;
        blocks[idx++] = `  title       = ${this.escapeString(policy.title)}`;
        if (policy.description) {
          blocks[idx++] = `  description = ${this.escapeString(policy.description)}`;
        }
        if (policy.category) {
          blocks[idx++] = `  category    = "${policy.category}"`;
        }
        blocks[idx++] = `  status      = "${policy.status}"`;
        blocks[idx++] = `  version     = "${policy.version || '1.0'}"`;
        if (policy.tags && policy.tags.length > 0) {
          blocks[idx++] = `  tags        = ${this.arrayToTerraform(policy.tags)}`;
        }
        blocks[idx++] = '}';
        blocks[idx++] = '';
      }
    }

    // Export risks
    if (data.risks && data.risks.length > 0) {
      blocks[idx++] = '# Risks';
      for (const risk of data.risks) {
        blocks[idx++] =
          `resource "gigachad_grc_risk" "${this.sanitizeName(risk.riskId || risk.id)}" {`;
        blocks[idx++] = `  risk_id     = "${risk.riskId || risk.id}"`;
        blocks[idx++] = `  title       = ${this.escapeString(risk.title)}`;
        if (risk.description) {
          blocks[idx++] = `  description = ${this.escapeString(risk.description)}`;
        }
        if (risk.category) {
          blocks[idx++] = `  category    = "${risk.category}"`;
        }
        if (risk.likelihood) {
          blocks[idx++] = `  likelihood  = "${risk.likelihood}"`;
        }
        if (risk.impact) {
          blocks[idx++] = `  impact      = "${risk.impact}"`;
        }
        blocks[idx++] = `  status      = "${risk.status}"`;
        if (risk.tags && risk.tags.length > 0) {
          blocks[idx++] = `  tags        = ${this.arrayToTerraform(risk.tags)}`;
        }
        blocks[idx++] = '}';
        blocks[idx++] = '';
      }
    }

    // Export vendors
    if (data.vendors && data.vendors.length > 0) {
      blocks[idx++] = '# Vendors';
      for (const vendor of data.vendors) {
        blocks[idx++] = `resource "gigachad_grc_vendor" "${this.sanitizeName(vendor.name)}" {`;
        blocks[idx++] = `  vendor_id   = "${vendor.vendorId || vendor.id}"`;
        blocks[idx++] = `  name        = ${this.escapeString(vendor.name)}`;
        if (vendor.description) {
          blocks[idx++] = `  description = ${this.escapeString(vendor.description)}`;
        }
        if (vendor.category) {
          blocks[idx++] = `  category    = "${vendor.category}"`;
        }
        blocks[idx++] = `  status      = "${vendor.status}"`;
        if (vendor.tags && vendor.tags.length > 0) {
          blocks[idx++] = `  tags        = ${this.arrayToTerraform(vendor.tags)}`;
        }
        blocks[idx++] = '}';
        blocks[idx++] = '';
      }
    }

    // Trim array to actual size and join
    const result = blocks.slice(0, idx).join('\n');

    const elapsed = Date.now() - startTime;
    this.logger.log(`Terraform export completed in ${elapsed}ms (${idx} lines)`);

    return result;
  }

  getMimeType(): string {
    return 'text/plain';
  }

  getFileExtension(): string {
    return 'tf';
  }

  private sanitizeName(name: string): string {
    // Convert to Terraform resource name (lowercase, underscores, alphanumeric)
    return name
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '')
      .substring(0, 50); // Limit length
  }

  private escapeString(str: string): string {
    // Escape quotes and newlines for Terraform strings
    const escaped = str.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
    return `"${escaped}"`;
  }

  private arrayToTerraform(arr: string[]): string {
    // Escape backslashes first, then quotes (order matters to avoid double-escaping)
    // This ensures complete sanitization for Terraform string literals
    return `[${arr
      .map((item) => {
        let escaped = item;
        // Iteratively replace all backslashes to ensure complete sanitization
        while (escaped.includes('\\')) {
          escaped = escaped.replace('\\', '\\\\');
        }
        // Then escape all quotes
        while (escaped.includes('"')) {
          escaped = escaped.replace('"', '\\"');
        }
        return `"${escaped}"`;
      })
      .join(', ')}]`;
  }
}
