import { NotAcceptableException, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true, // Strip any properties that are not defined in the DTO
    forbidNonWhitelisted: true, // Throw an error if non-whitelisted properties are found
    transform: true, // Automatically transform payloads to the DTO classes
    exceptionFactory: (errors) => {
      return new NotAcceptableException(
        errors.map(err => ({
          field: err.property,
          errors: Object.values(err.constraints)
        }))
      );
    }
  }));
  await app.listen(3000);
}
bootstrap();
