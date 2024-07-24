import { IsNotEmpty, IsString } from "class-validator";

export class ResetPasswordDto {
  @IsNotEmpty({ message: 'Password is required' })
  @IsString()
  password: string;

  @IsNotEmpty({ message: 'Confirm password is required' })
  @IsString()
  confirmPassword: string;
}
