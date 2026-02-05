// ===========================================
// Types
// ===========================================

export type ExportFormat = 'csv' | 'xlsx' | 'json';

interface ExportColumn<T> {
  key: keyof T | string;
  header: string;
  transform?: (value: unknown, row: T) => string | number;
}

interface ExportOptions<T> {
  filename: string;
  columns: ExportColumn<T>[];
  data: T[];
  format: ExportFormat;
  sheetName?: string;
}

// ===========================================
// CSV Export
// ===========================================

/**
 * SECURITY: Sanitize CSV value to prevent formula injection attacks.
 * When CSV is opened in Excel, values starting with =, +, -, @, |, or tab
 * can be interpreted as formulas and execute malicious code.
 * Prefixing with a single quote (') tells Excel to treat it as text.
 */
function sanitizeCsvFormula(value: string): string {
  const dangerousChars = ['=', '+', '-', '@', '|', '\t', '\r'];
  if (dangerousChars.some((char) => value.startsWith(char))) {
    return "'" + value;
  }
  return value;
}

function escapeCSVValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  // SECURITY: Sanitize formula injection before processing
  const str = sanitizeCsvFormula(String(value));
  // Escape quotes and wrap in quotes if contains comma, newline, or quote
  if (str.includes(',') || str.includes('\n') || str.includes('"')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function generateCSV<T>(columns: ExportColumn<T>[], data: T[]): string {
  const headers = columns.map((col) => escapeCSVValue(col.header)).join(',');

  const rows = data.map((row) => {
    return columns
      .map((col) => {
        const key = col.key as string;
        const rawValue = key.includes('.')
          ? key
              .split('.')
              .reduce(
                (obj: Record<string, unknown>, k) => obj?.[k] as Record<string, unknown>,
                row as unknown as Record<string, unknown>
              )
          : (row as Record<string, unknown>)[key];
        const value = col.transform ? col.transform(rawValue, row) : rawValue;
        return escapeCSVValue(value);
      })
      .join(',');
  });

  return [headers, ...rows].join('\n');
}

// ===========================================
// Excel Export (Lazy Loaded with ExcelJS)
// ===========================================

// ExcelJS type for dynamic import
type ExcelJSModule = typeof import('exceljs');

// Cache the ExcelJS module after first load
let excelJSModule: ExcelJSModule | null = null;

async function loadExcelJS(): Promise<ExcelJSModule> {
  if (!excelJSModule) {
    // Dynamic import - exceljs is only loaded when actually needed for Excel export
    excelJSModule = await import('exceljs');
  }
  return excelJSModule;
}

async function generateExcel<T>(
  columns: ExportColumn<T>[],
  data: T[],
  sheetName: string
): Promise<ArrayBuffer> {
  const ExcelJS = await loadExcelJS();

  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet(sheetName);

  // Add headers
  const headers = columns.map((col) => col.header);
  const headerRow = worksheet.addRow(headers);

  // Style header row
  headerRow.eachCell((cell) => {
    cell.font = { bold: true };
    cell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FFE0E0E0' },
    };
  });

  // Add data rows
  data.forEach((row) => {
    const rowData = columns.map((col) => {
      const key = col.key as string;
      const rawValue = key.includes('.')
        ? key
            .split('.')
            .reduce(
              (obj: Record<string, unknown>, k) => obj?.[k] as Record<string, unknown>,
              row as unknown as Record<string, unknown>
            )
        : (row as Record<string, unknown>)[key];
      return col.transform ? col.transform(rawValue, row) : rawValue;
    });
    worksheet.addRow(rowData);
  });

  // Auto-size columns
  worksheet.columns.forEach((column, i) => {
    const maxLength = Math.max(
      headers[i]?.length || 10,
      ...data.map((row) => {
        const key = columns[i].key as string;
        const rawValue = key.includes('.')
          ? key
              .split('.')
              .reduce(
                (obj: Record<string, unknown>, k) => obj?.[k] as Record<string, unknown>,
                row as unknown as Record<string, unknown>
              )
          : (row as Record<string, unknown>)[key];
        const value = columns[i].transform ? columns[i].transform(rawValue, row) : rawValue;
        return String(value ?? '').length;
      })
    );
    column.width = Math.min(maxLength + 2, 50);
  });

  const buffer = await workbook.xlsx.writeBuffer();
  return buffer as ArrayBuffer;
}

// ===========================================
// JSON Export
// ===========================================

function generateJSON<T>(columns: ExportColumn<T>[], data: T[]): string {
  const exportData = data.map((row) => {
    const obj: Record<string, unknown> = {};
    columns.forEach((col) => {
      const key = col.key as string;
      const rawValue = key.includes('.')
        ? key
            .split('.')
            .reduce(
              (o: Record<string, unknown>, k) => o?.[k] as Record<string, unknown>,
              row as unknown as Record<string, unknown>
            )
        : (row as Record<string, unknown>)[key];
      obj[col.header] = col.transform ? col.transform(rawValue, row) : rawValue;
    });
    return obj;
  });
  return JSON.stringify(exportData, null, 2);
}

// ===========================================
// Download Utility
// ===========================================

function downloadFile(content: string | ArrayBuffer, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// ===========================================
// Main Export Function (Now Async)
// ===========================================

export async function exportData<T>(options: ExportOptions<T>): Promise<void> {
  const { filename, columns, data, format, sheetName = 'Sheet1' } = options;
  const timestamp = new Date().toISOString().split('T')[0];
  const fullFilename = `${filename}_${timestamp}`;

  switch (format) {
    case 'csv': {
      const csv = generateCSV(columns, data);
      downloadFile(csv, `${fullFilename}.csv`, 'text/csv;charset=utf-8;');
      break;
    }
    case 'xlsx': {
      // Excel export now dynamically loads xlsx library
      const excelBuffer = await generateExcel(columns, data, sheetName);
      downloadFile(
        excelBuffer,
        `${fullFilename}.xlsx`,
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      );
      break;
    }
    case 'json': {
      const json = generateJSON(columns, data);
      downloadFile(json, `${fullFilename}.json`, 'application/json');
      break;
    }
  }
}

// ===========================================
// Pre-defined Export Configurations
// ===========================================

export const exportConfigs = {
  controls: [
    { key: 'controlId', header: 'Control ID' },
    { key: 'title', header: 'Title' },
    { key: 'description', header: 'Description' },
    {
      key: 'status',
      header: 'Status',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    { key: 'category', header: 'Category' },
    { key: 'owner', header: 'Owner' },
    {
      key: 'implementationDate',
      header: 'Implementation Date',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
    {
      key: 'lastReviewDate',
      header: 'Last Review Date',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
    {
      key: 'nextReviewDate',
      header: 'Next Review Date',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
  ],

  risks: [
    { key: 'title', header: 'Title' },
    { key: 'description', header: 'Description' },
    {
      key: 'riskLevel',
      header: 'Risk Level',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    {
      key: 'status',
      header: 'Status',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    { key: 'category', header: 'Category' },
    { key: 'likelihood', header: 'Likelihood' },
    { key: 'impact', header: 'Impact' },
    { key: 'owner', header: 'Owner' },
    { key: 'treatmentPlan', header: 'Treatment Plan' },
    {
      key: 'createdAt',
      header: 'Created Date',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
  ],

  vendors: [
    { key: 'name', header: 'Vendor Name' },
    { key: 'description', header: 'Description' },
    { key: 'category', header: 'Category' },
    {
      key: 'riskTier',
      header: 'Risk Tier',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    {
      key: 'status',
      header: 'Status',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    { key: 'primaryContact', header: 'Primary Contact' },
    { key: 'contactEmail', header: 'Contact Email' },
    { key: 'website', header: 'Website' },
    {
      key: 'contractStartDate',
      header: 'Contract Start',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
    {
      key: 'contractEndDate',
      header: 'Contract End',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
  ],

  policies: [
    { key: 'title', header: 'Title' },
    { key: 'description', header: 'Description' },
    {
      key: 'status',
      header: 'Status',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    { key: 'category', header: 'Category' },
    { key: 'version', header: 'Version' },
    { key: 'owner', header: 'Owner' },
    {
      key: 'effectiveDate',
      header: 'Effective Date',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
    {
      key: 'reviewDate',
      header: 'Review Date',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
    { key: 'approvedBy', header: 'Approved By' },
  ],

  assets: [
    { key: 'name', header: 'Asset Name' },
    { key: 'description', header: 'Description' },
    {
      key: 'type',
      header: 'Type',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    {
      key: 'criticality',
      header: 'Criticality',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    {
      key: 'status',
      header: 'Status',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    { key: 'owner', header: 'Owner' },
    { key: 'location', header: 'Location' },
    { key: 'dataClassification', header: 'Data Classification' },
  ],

  audits: [
    { key: 'name', header: 'Audit Name' },
    {
      key: 'type',
      header: 'Type',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    {
      key: 'status',
      header: 'Status',
      transform: (v: unknown) =>
        String(v)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (l) => l.toUpperCase()),
    },
    { key: 'auditor', header: 'Auditor' },
    {
      key: 'startDate',
      header: 'Start Date',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
    {
      key: 'endDate',
      header: 'End Date',
      transform: (v: unknown) => (v ? new Date(v as string).toLocaleDateString() : ''),
    },
    { key: 'framework', header: 'Framework' },
  ],
};

export default exportData;
