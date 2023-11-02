import { Controller, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { Body, Post } from '@nestjs/common';
import { SignUpDto } from './dto/sign-up.dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto/sign-in.dto';
import { Auth } from './decorators/auth.decorators';

import { AuthType } from './enums/auth-type.enum';
@Auth(AuthType.None)
@Controller('authentication')
export class AuthenticationController {
  constructor(private readonly authService: AuthenticationService) {

  }
  @Post('sign-up')
  async signUp(@Body() signUpDto: SignUpDto) {
    await this.authService.signUp(signUpDto);
  }
  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  async signIn(
    /*@Res({ passthrough: true }) response: Response,*/
    @Body() signInDto: SignInDto) {
    return await this.authService.signIn(signInDto);
    /* response.cookie('Authentication', accessToken, { 
    secure: true,
    httpOnly: true,
    sameSite: true,
    });*/
  }
}
