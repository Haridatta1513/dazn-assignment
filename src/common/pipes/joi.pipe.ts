import {
  HttpException,
  HttpStatus,
  Injectable,
  PipeTransform,
} from '@nestjs/common';
import { ObjectSchema } from 'joi';

@Injectable()
export class JoiValidationPipe implements PipeTransform {
  constructor(private schema: ObjectSchema) {}

  transform(value: any) {
    const result = this.schema.validate(value, { convert: true });
    if (result?.error) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: result.error.message,
        },
        HttpStatus.BAD_REQUEST,
      );
    }
    return result.value;
  }
}
