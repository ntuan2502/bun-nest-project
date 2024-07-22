import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Invalid email' })
  readonly email: string;

  @IsNotEmpty({ message: 'Password is required' })
  @IsString()
  readonly password: string;
}
