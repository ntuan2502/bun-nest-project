import { IsNotEmpty, IsString } from "class-validator";

export class TokenDto {
  @IsNotEmpty({ message: 'Token is required' })
  @IsString()
  token: string;
}