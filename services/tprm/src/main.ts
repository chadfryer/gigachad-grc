import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule);

  // SECURITY: Add Helmet for security headers
  app.use(
    helmet({
      contentSecurityPolicy: false, // Disable for API service
    })
  );

  // CORS - use CORS_ORIGINS (plural) for consistency across services
  const corsOrigins =
    process.env.CORS_ORIGINS?.split(',') || process.env.CORS_ORIGIN?.split(',') || [];

  if (process.env.NODE_ENV === 'production' && corsOrigins.length === 0) {
    throw new Error('CORS_ORIGINS must be configured in production');
  }

  // Fall back to localhost only in development
  const origins =
    corsOrigins.length > 0 ? corsOrigins : ['http://localhost:3000', 'http://localhost:5173'];

  app.enableCors({
    origin: origins,
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    })
  );

  const config = new DocumentBuilder()
    .setTitle('TPRM Service API')
    .setDescription('Third Party Risk Management API')
    .setVersion('1.0')
    .addTag('vendors')
    .addTag('assessments')
    .addTag('contracts')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = process.env.PORT || 3005;
  await app.listen(port);
  logger.log(`TPRM service running on port ${port}`);
}

bootstrap();
