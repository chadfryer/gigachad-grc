import { IsString, IsOptional, IsBoolean, IsEnum, ValidateNested, IsNumber, Min, Max, IsEmail } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

// Email Provider Types
export enum EmailProvider {
  DISABLED = 'disabled',
  SMTP = 'smtp',
  SENDGRID = 'sendgrid',
  SES = 'ses',
}

// SMTP Configuration
export class SmtpConfigDto {
  @ApiProperty({ description: 'SMTP server host' })
  @IsString()
  host: string;

  @ApiProperty({ description: 'SMTP server port', default: 587 })
  @IsNumber()
  @Min(1)
  @Max(65535)
  port: number;

  @ApiPropertyOptional({ description: 'SMTP username' })
  @IsOptional()
  @IsString()
  user?: string;

  @ApiPropertyOptional({ description: 'SMTP password' })
  @IsOptional()
  @IsString()
  password?: string;

  @ApiProperty({ description: 'Use TLS/SSL', default: true })
  @IsBoolean()
  secure: boolean;
}

// AWS SES Configuration
export class SesConfigDto {
  @ApiProperty({ description: 'AWS region', default: 'us-east-1' })
  @IsString()
  region: string;

  @ApiPropertyOptional({ description: 'AWS Access Key ID' })
  @IsOptional()
  @IsString()
  accessKeyId?: string;

  @ApiPropertyOptional({ description: 'AWS Secret Access Key' })
  @IsOptional()
  @IsString()
  secretAccessKey?: string;
}

// Update Email Configuration
export class UpdateEmailConfigDto {
  @ApiProperty({ enum: EmailProvider, description: 'Email provider to use' })
  @IsEnum(EmailProvider)
  emailProvider: EmailProvider;

  @ApiPropertyOptional({ description: 'From email address' })
  @IsOptional()
  @IsEmail()
  emailFromAddress?: string;

  @ApiPropertyOptional({ description: 'From display name' })
  @IsOptional()
  @IsString()
  emailFromName?: string;

  @ApiPropertyOptional({ description: 'SMTP configuration (when provider is smtp)' })
  @IsOptional()
  @ValidateNested()
  @Type(() => SmtpConfigDto)
  smtpConfig?: SmtpConfigDto;

  @ApiPropertyOptional({ description: 'SendGrid API key (when provider is sendgrid)' })
  @IsOptional()
  @IsString()
  sendgridApiKey?: string;

  @ApiPropertyOptional({ description: 'AWS SES configuration (when provider is ses)' })
  @IsOptional()
  @ValidateNested()
  @Type(() => SesConfigDto)
  sesConfig?: SesConfigDto;
}

// Update Slack Configuration
export class UpdateSlackConfigDto {
  @ApiProperty({ description: 'Enable Slack notifications' })
  @IsBoolean()
  slackNotificationsEnabled: boolean;

  @ApiPropertyOptional({ description: 'Slack webhook URL' })
  @IsOptional()
  @IsString()
  slackWebhookUrl?: string;

  @ApiPropertyOptional({ description: 'Slack bot token (xoxb-...)' })
  @IsOptional()
  @IsString()
  slackBotToken?: string;

  @ApiPropertyOptional({ description: 'Default Slack channel for notifications' })
  @IsOptional()
  @IsString()
  slackDefaultChannel?: string;

  @ApiPropertyOptional({ description: 'Slack workspace name (for display)' })
  @IsOptional()
  @IsString()
  slackWorkspaceName?: string;
}

// Default Notification Preferences
export class NotificationTypePreferenceDto {
  @ApiProperty({ description: 'Send email notifications' })
  @IsBoolean()
  email: boolean;

  @ApiProperty({ description: 'Send Slack notifications' })
  @IsBoolean()
  slack: boolean;

  @ApiProperty({ description: 'Show in-app notifications' })
  @IsBoolean()
  inApp: boolean;
}

export class UpdateDefaultNotificationsDto {
  @ApiPropertyOptional({ description: 'Compliance drift notification preferences' })
  @IsOptional()
  @ValidateNested()
  @Type(() => NotificationTypePreferenceDto)
  complianceDrift?: NotificationTypePreferenceDto;

  @ApiPropertyOptional({ description: 'Evidence expiring notification preferences' })
  @IsOptional()
  @ValidateNested()
  @Type(() => NotificationTypePreferenceDto)
  evidenceExpiring?: NotificationTypePreferenceDto;

  @ApiPropertyOptional({ description: 'Assessment due notification preferences' })
  @IsOptional()
  @ValidateNested()
  @Type(() => NotificationTypePreferenceDto)
  assessmentDue?: NotificationTypePreferenceDto;

  @ApiPropertyOptional({ description: 'Vendor risk notification preferences' })
  @IsOptional()
  @ValidateNested()
  @Type(() => NotificationTypePreferenceDto)
  vendorRisk?: NotificationTypePreferenceDto;

  @ApiPropertyOptional({ description: 'Policy review notification preferences' })
  @IsOptional()
  @ValidateNested()
  @Type(() => NotificationTypePreferenceDto)
  policyReview?: NotificationTypePreferenceDto;

  @ApiPropertyOptional({ description: 'Control failure notification preferences' })
  @IsOptional()
  @ValidateNested()
  @Type(() => NotificationTypePreferenceDto)
  controlFailure?: NotificationTypePreferenceDto;

  @ApiPropertyOptional({ description: 'Task assigned notification preferences' })
  @IsOptional()
  @ValidateNested()
  @Type(() => NotificationTypePreferenceDto)
  taskAssigned?: NotificationTypePreferenceDto;
}

// Test Email Request
export class TestEmailDto {
  @ApiProperty({ description: 'Email address to send test to' })
  @IsEmail()
  recipientEmail: string;
}

// Test Slack Request
export class TestSlackDto {
  @ApiPropertyOptional({ description: 'Channel to send test message to (optional, uses default if not provided)' })
  @IsOptional()
  @IsString()
  channel?: string;
}

// Response DTOs
export class NotificationConfigResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  organizationId: string;

  // Email Configuration (masked)
  @ApiProperty({ enum: EmailProvider })
  emailProvider: EmailProvider;

  @ApiPropertyOptional()
  emailFromAddress?: string;

  @ApiPropertyOptional()
  emailFromName?: string;

  @ApiPropertyOptional({ description: 'SMTP config (passwords masked)' })
  smtpConfig?: {
    host: string;
    port: number;
    user?: string;
    password?: string; // Will be masked like '••••••••'
    secure: boolean;
  };

  @ApiPropertyOptional({ description: 'SendGrid API key (masked)' })
  sendgridApiKey?: string;

  @ApiPropertyOptional({ description: 'SES config (secrets masked)' })
  sesConfig?: {
    region: string;
    accessKeyId?: string; // Will be masked
    secretAccessKey?: string; // Will be masked
  };

  // Slack Configuration (masked)
  @ApiProperty()
  slackNotificationsEnabled: boolean;

  @ApiPropertyOptional()
  slackWebhookUrl?: string; // Will be masked

  @ApiPropertyOptional()
  slackBotToken?: string; // Will be masked

  @ApiPropertyOptional()
  slackDefaultChannel?: string;

  @ApiPropertyOptional()
  slackWorkspaceName?: string;

  // Default Notifications
  @ApiProperty()
  defaultNotifications: Record<string, NotificationTypePreferenceDto>;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}

export class TestResultDto {
  @ApiProperty()
  success: boolean;

  @ApiProperty()
  message: string;
}




