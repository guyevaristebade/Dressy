import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  @IsNotEmpty()
  readonly email: string;

  @IsNotEmpty()
  @MinLength(6)
  readonly password!: string;

  @IsString()
  @IsNotEmpty()
  readonly fullName!: string;

  @IsString()
  @IsNotEmpty()
  readonly profileName!: string;
}
