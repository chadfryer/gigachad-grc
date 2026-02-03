import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsBoolean } from 'class-validator';

export class LogoutDto {
  @ApiPropertyOptional({ description: 'Reason for logout' })
  @IsOptional()
  @IsString()
  reason?: string;
}

export class LogoutAllDevicesDto {
  @ApiPropertyOptional({ description: 'Reason for logging out all devices' })
  @IsOptional()
  @IsString()
  reason?: string;
}

export class LogoutResponseDto {
  @ApiProperty({ description: 'Whether the logout was successful' })
  success: boolean;

  @ApiProperty({ description: 'Message describing the result' })
  message: string;

  @ApiPropertyOptional({ description: 'Number of tokens/sessions revoked' })
  revokedCount?: number;
}
