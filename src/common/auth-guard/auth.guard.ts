import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { IVerifyTokenResponse } from '../interface';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    try {
      const req = context.switchToHttp().getRequest();
      const token = req.headers['authorization'].replace('Bearer', '').trim();
      const user = jwt.verify(token, process.env.JWT_SECRET_KEY);
      req.user = user;
      return true;
    } catch (err) {
      return false;
    }
  }
  verifyToken(token: string): IVerifyTokenResponse {
    if (!token) {
      return { isValid: false };
    }
    const publicKey = fs.readFileSync('public.pem', 'utf-8');
    try {
      const decoded = jwt.verify(token, publicKey, {
        algorithms: ['RS256'],
      });
      const id = typeof decoded === 'string' ? decoded : decoded?.sub;
      return {
        isValid: true,
        id: id,
      };
    } catch (err) {
      return {
        isValid: false,
      };
    }
  }
}
