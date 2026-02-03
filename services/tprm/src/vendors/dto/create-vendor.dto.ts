import { IsString, IsOptional, IsEmail, IsIn, ValidateIf, MaxLength, IsUrl } from 'class-validator';

export class CreateVendorDto {
  // organizationId is injected from user context in controller
  @IsString()
  @IsOptional()
  @MaxLength(100)
  organizationId?: string;

  // vendorId is auto-generated if not provided
  @IsString()
  @IsOptional()
  @MaxLength(100)
  vendorId?: string;

  @IsString()
  @MaxLength(255)
  name: string;

  @IsString()
  @IsOptional()
  @MaxLength(255)
  legalName?: string;

  @IsIn(['software_vendor', 'cloud_provider', 'professional_services', 'hardware_vendor', 'consultant'])
  @IsOptional()
  category?: string;

  @IsIn(['tier_1', 'tier_2', 'tier_3', 'tier_4'])
  @IsOptional()
  tier?: string;

  @IsIn(['active', 'inactive', 'pending_onboarding', 'offboarding', 'terminated'])
  @IsOptional()
  status?: string;

  @IsString()
  @IsOptional()
  @MaxLength(2000)
  description?: string;

  @IsOptional()
  @IsUrl({}, { message: 'website must be a valid URL' })
  @MaxLength(500)
  website?: string;

  @IsString()
  @IsOptional()
  @MaxLength(255)
  primaryContact?: string;

  // Only validate email format if a non-empty value is provided
  @ValidateIf((o) => o.primaryContactEmail && o.primaryContactEmail.length > 0)
  @IsEmail()
  @IsOptional()
  @MaxLength(255)
  primaryContactEmail?: string;

  @IsString()
  @IsOptional()
  @MaxLength(50)
  primaryContactPhone?: string;

  @IsString()
  @IsOptional()
  @MaxLength(5000)
  notes?: string;

  @IsString()
  @IsOptional()
  @MaxLength(50)
  reviewFrequency?: string; // Supports predefined (monthly, quarterly, etc.) or custom_X format
}
