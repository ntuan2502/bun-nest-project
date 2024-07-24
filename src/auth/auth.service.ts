import { TokenDto } from './dto/token.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { excludePassword } from 'src/common/utils';
import { jwtConstants } from './constants';
import { MailerService } from '@nestjs-modules/mailer';
import { v4 as uuidv4 } from 'uuid';
import { convertToTimeZone } from 'src/common/time-utils';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  async register(registerDto: RegisterDto) {
    const { name, email, password } = registerDto;

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    const hashedPassword = await bcrypt.hash(password, 10);

    if (existingUser) {
      if (existingUser.verified) {
        throw new ConflictException('Email already exists');
      } else {
        // Xử lý trường hợp tài khoản chưa được xác thực
        const token = uuidv4();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1);
        const expiresAtFormatted = convertToTimeZone(expiresAt);

        await this.prisma.emailVerification.upsert({
          where: { userId: existingUser.id },
          update: {
            token,
            expiresAt,
          },
          create: {
            token,
            userId: existingUser.id,
            expiresAt,
          },
        });

        await this.mailerService.sendMail({
          to: email,
          subject: 'Email Verification',
          template: './verify-email',
          context: {
            name: existingUser.name,
            token,
            url: process.env.URL,
            expiresAt: expiresAtFormatted,
          },
        });

        return {
          message:
            'Email already exists but not verified. Verification email sent again.',
        };
      }
    }

    // Tạo tài khoản mới nếu email chưa tồn tại
    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);
    const expiresAtFormatted = convertToTimeZone(expiresAt);

    await this.prisma.emailVerification.create({
      data: {
        token,
        userId: user.id,
        expiresAt,
      },
    });

    await this.mailerService.sendMail({
      to: email,
      subject: 'Email Verification',
      template: './verify-email',
      context: {
        name: user.name,
        token,
        url: process.env.URL,
        expiresAt: expiresAtFormatted,
      },
    });

    return {
      message:
        'User registered successfully, please check your email for verification link',
    };

    // return excludePassword(user);
  }

  async verifyEmail(tokenDto: TokenDto) {
    const { token } = tokenDto;
    const verificationToken = await this.prisma.emailVerification.findUnique({
      where: { token },
    });

    if (!verificationToken) {
      throw new UnauthorizedException('Invalid or expired verification token');
    }

    if (verificationToken.expiresAt < new Date()) {
      await this.prisma.emailVerification.delete({ where: { token } });
      throw new UnauthorizedException('Verification token expired');
    }

    await this.prisma.user.update({
      where: { id: verificationToken.userId },
      data: { verified: true },
    });

    await this.prisma.emailVerification.delete({ where: { token } });

    return { message: 'Email verified successfully' };
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const payload = { sub: user.id, email: user.email };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = uuidv4();

    const accessExpiresAt = new Date();
    accessExpiresAt.setMinutes(accessExpiresAt.getMinutes() + 15); // Access token expires in 15 minutes

    const refreshExpiresAt = new Date();
    refreshExpiresAt.setDate(refreshExpiresAt.getDate() + 7); // Refresh token expires in 7 days

    await this.prisma.userSession.create({
      data: {
        accessToken,
        refreshToken,
        userId: user.id,
        accessExpiresAt,
        refreshExpiresAt,
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto) {
    const { refreshToken } = refreshTokenDto;
    const tokenRecord = await this.prisma.userSession.findUnique({
      where: { refreshToken },
    });

    if (!tokenRecord || tokenRecord.refreshExpiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: tokenRecord.userId },
    });
    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }

    const payload = { sub: user.id, email: user.email };
    const newAccessToken = this.jwtService.sign(payload, { expiresIn: '15m' });

    const newAccessExpiresAt = new Date();
    newAccessExpiresAt.setMinutes(newAccessExpiresAt.getMinutes() + 15); // New access token expires in 15 minutes

    await this.prisma.userSession.update({
      where: { id: tokenRecord.id },
      data: {
        accessToken: newAccessToken,
        accessExpiresAt: newAccessExpiresAt,
      },
    });

    return {
      accessToken: newAccessToken,
    };
  }

  async logoutAll(userId: number) {
    await this.prisma.userSession.deleteMany({
      where: {
        userId: userId,
      },
    });
    return { message: 'Logged out successfully' };
  }

  async logout(refreshTokenDto: RefreshTokenDto) {
    const { refreshToken } = refreshTokenDto;
    const token = await this.prisma.userSession.findUnique({
      where: { refreshToken },
    });

    if (!token) {
      throw new NotFoundException('Token not found');
    }

    await this.prisma.userSession.delete({
      where: { refreshToken },
    });

    return { message: 'Logged out from specific session successfully' };
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('Email not found');
    }

    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);
    const expiresAtFormatted = convertToTimeZone(expiresAt);

    await this.prisma.forgotPassword.create({
      data: {
        token,
        userId: user.id,
        expiresAt,
      },
    });

    await this.mailerService.sendMail({
      to: email,
      subject: 'Password Reset',
      template: './reset-password',
      context: {
        name: user.name,
        token,
        url: process.env.URL,
        expiresAt: expiresAtFormatted,
      },
    });

    return { message: 'Password reset email sent' };
  }

  async resetPassword(tokenDto: TokenDto, resetPasswordDto: ResetPasswordDto) {
    const { token } = tokenDto;
    const { password, confirmPassword } = resetPasswordDto;

    if (password !== confirmPassword) {
      throw new UnauthorizedException('Passwords do not match');
    }

    const resetToken = await this.prisma.forgotPassword.findUnique({
      where: { token },
    });

    if (!resetToken) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    if (resetToken.expiresAt < new Date()) {
      await this.prisma.forgotPassword.delete({ where: { token } });
      throw new UnauthorizedException('Token expired');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: resetToken.userId },
    });
    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword },
    });

    await this.prisma.forgotPassword.delete({ where: { token } });

    return { message: 'Password reset successfully' };
  }
}
