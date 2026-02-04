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

  // SECURITY: Configure CORS with explicit origin restrictions
  // Open CORS (enableCors() without options) is a security risk
  const corsOrigins = process.env.CORS_ORIGINS?.split(',') || [];

  if (process.env.NODE_ENV === 'production' && corsOrigins.length === 0) {
    throw new Error('CORS_ORIGINS must be configured in production');
  }

  // Fall back to localhost only in development
  const origins =
    corsOrigins.length > 0 ? corsOrigins : ['http://localhost:3000', 'http://localhost:5173'];

  app.enableCors({
    origin: origins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-organization-id'],
  });

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    })
  );

  // Swagger documentation
  const config = new DocumentBuilder()
    .setTitle('Trust API')
    .setDescription('Security questionnaires, knowledge base, and trust center management')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = process.env.PORT || 3006;
  await app.listen(port);
  logger.log(`Trust service running on port ${port}`);
}
bootstrap();
