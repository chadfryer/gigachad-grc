import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { FileValidatorService, FileCategory, ALLOWED_FILE_TYPES } from './file-validator.service';
import { SetMetadata } from '@nestjs/common';

/**
 * Metadata key for specifying file upload options on a route
 */
export const FILE_UPLOAD_OPTIONS_KEY = 'file_upload_options';

/**
 * Options for file upload validation on a specific route
 */
export interface FileUploadOptions {
  /** The category of files allowed (determines MIME types and size limits) */
  category: FileCategory;
  /** Optional custom max file size in bytes (overrides category default) */
  maxSize?: number;
  /** Optional list of additional allowed MIME types */
  additionalMimeTypes?: string[];
  /** Field name(s) containing uploaded files (default: 'file') */
  fieldNames?: string[];
  /** Whether to allow multiple files (default: true) */
  allowMultiple?: boolean;
  /** Maximum number of files if multiple (default: 10) */
  maxFiles?: number;
}

/**
 * Decorator to specify file upload validation options for a route
 *
 * @example
 * ```typescript
 * @Post('upload')
 * @FileUpload({ category: 'evidence', maxSize: 10 * 1024 * 1024 })
 * @UseInterceptors(FileInterceptor('file'), FileUploadValidationInterceptor)
 * async uploadFile(@UploadedFile() file: Express.Multer.File) {
 *   // File has been validated
 * }
 * ```
 */
export const FileUpload = (options: FileUploadOptions) =>
  SetMetadata(FILE_UPLOAD_OPTIONS_KEY, options);

/**
 * SECURITY: Unified file upload validation interceptor
 *
 * This interceptor applies comprehensive file validation to all upload endpoints:
 * - Magic bytes verification (file signature check)
 * - MIME type allowlist validation
 * - Dangerous extension blocking (.exe, .bat, .sh, etc.)
 * - Double extension detection (.pdf.exe)
 * - Null byte injection prevention
 * - Filename sanitization
 * - File size limits
 *
 * Use the @FileUpload decorator to specify validation options per route,
 * or apply this interceptor globally with default settings.
 */
@Injectable()
export class FileUploadValidationInterceptor implements NestInterceptor {
  private readonly logger = new Logger(FileUploadValidationInterceptor.name);
  private readonly defaultCategory: FileCategory = 'evidence';
  private readonly defaultFieldNames = [
    'file',
    'files',
    'document',
    'documents',
    'attachment',
    'attachments',
  ];

  constructor(private readonly fileValidator: FileValidatorService) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<unknown>> {
    const request = context.switchToHttp().getRequest();

    // Get route-specific options from metadata
    const reflector = context.getHandler();
    const options: FileUploadOptions | undefined = Reflect.getMetadata(
      FILE_UPLOAD_OPTIONS_KEY,
      reflector
    );

    const category = options?.category || this.defaultCategory;
    const fieldNames = options?.fieldNames || this.defaultFieldNames;
    const maxFiles = options?.maxFiles || 10;
    const allowMultiple = options?.allowMultiple !== false;

    // Check for uploaded files
    const files = this.extractFiles(request, fieldNames);

    if (files.length === 0) {
      // No files to validate, continue
      return next.handle();
    }

    // Validate file count
    if (!allowMultiple && files.length > 1) {
      throw new BadRequestException('Only one file is allowed');
    }

    if (files.length > maxFiles) {
      throw new BadRequestException(`Maximum ${maxFiles} files allowed`);
    }

    // Get allowed MIME types for category
    const allowedMimeTypes = [
      ...(ALLOWED_FILE_TYPES[category] || ALLOWED_FILE_TYPES.evidence),
      ...(options?.additionalMimeTypes || []),
    ];

    // Validate each file
    for (const file of files) {
      try {
        // Use FileValidatorService for comprehensive validation
        await this.fileValidator.validateFile(file, {
          allowedMimeTypes,
          maxSizeBytes: options?.maxSize,
          category,
        });
      } catch (error) {
        this.logger.warn(
          `SECURITY: File upload rejected - File: ${file.originalname}, ` +
            `MIME: ${file.mimetype}, Size: ${file.size}, ` +
            `Error: ${error.message}`
        );
        throw error;
      }
    }

    this.logger.debug(`File upload validated: ${files.length} file(s), category: ${category}`);

    return next.handle();
  }

  /**
   * Extract uploaded files from request
   */
  private extractFiles(
    request: {
      file?: Express.Multer.File;
      files?: Express.Multer.File[] | Record<string, Express.Multer.File[]>;
    },
    fieldNames: string[]
  ): Express.Multer.File[] {
    const files: Express.Multer.File[] = [];

    // Single file upload (FileInterceptor)
    if (request.file) {
      files.push(request.file);
    }

    // Multiple files - array (FilesInterceptor)
    if (Array.isArray(request.files)) {
      files.push(...request.files);
    }

    // Multiple fields (FileFieldsInterceptor)
    if (request.files && typeof request.files === 'object' && !Array.isArray(request.files)) {
      for (const fieldName of fieldNames) {
        const fieldFiles = request.files[fieldName];
        if (Array.isArray(fieldFiles)) {
          files.push(...fieldFiles);
        }
      }
    }

    return files;
  }
}

/**
 * SECURITY: Global file upload interceptor provider
 *
 * Apply this to app.module.ts to enable file validation for all routes:
 *
 * @example
 * ```typescript
 * import { APP_INTERCEPTOR } from '@nestjs/core';
 * import { FileUploadValidationInterceptor } from './common/file-upload.interceptor';
 *
 * @Module({
 *   providers: [
 *     {
 *       provide: APP_INTERCEPTOR,
 *       useClass: FileUploadValidationInterceptor,
 *     },
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
export const GlobalFileUploadValidationProvider = {
  provide: 'APP_INTERCEPTOR',
  useClass: FileUploadValidationInterceptor,
};
