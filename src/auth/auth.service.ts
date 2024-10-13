import { PrismaService } from 'src/prisma.service';
import { AuthBody } from './auth.controller';
import { Injectable } from '@nestjs/common';
import { hash, compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserPayload } from './jwt.strategy';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}
  async login({ authBody }: { authBody: AuthBody }) {
    const { email, password } = authBody;

    const existingUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (!existingUser) {
      throw new Error("L'utilisateur n'existe pas.");
    }
    const isPasswordValid = await this.isPasswordValid({
      password,
      hashedPassword: existingUser.password,
    });
    if (!isPasswordValid) {
      throw new Error('Le mot de passe est invalide');
    }
    return this.authenticateUser({ userId: existingUser.id });
  }

  //   const hashPassword = await this.hashPassword({ password });

  private async hashPassword({ password }: { password: string }) {
    const hashedPassword = await hash(password, 10);
    return hashedPassword;
  }
  private async isPasswordValid({
    password,
    hashedPassword,
  }: {
    password: string;
    hashedPassword: string;
  }) {
    const isPasswordValid = await compare(password, hashedPassword);
    return isPasswordValid;
  }

  private async authenticateUser({ userId }: { userId: string }) {
    const payload: UserPayload = { userId };
    return {
      access_tokent: this.jwtService.sign(payload),
    };
  }
}
