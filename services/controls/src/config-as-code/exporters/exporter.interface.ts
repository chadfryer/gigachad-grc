import { ConfigFormat } from '../dto/export-config.dto';

export interface ResourceData {
  controls?: any[];
  frameworks?: any[];
  policies?: any[];
  risks?: any[];
  evidence?: any[];
  vendors?: any[];
}

export interface Exporter {
  /**
   * Export resources to the specified format
   */
  export(data: ResourceData, format: ConfigFormat): string;

  /**
   * Get the MIME type for the exported content
   */
  getMimeType(): string;

  /**
   * Get the file extension for the exported content
   */
  getFileExtension(): string;
}

