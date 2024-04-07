import {
  Body,
  Controller,
  DefaultValuePipe,
  Get,
  Inject,
  Post,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RequireLogin, UserInfo } from 'src/custom.decorator';
import { generateParseIntPipe } from 'src/utils/generateParseIntPipe';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { UpdateUserPasswordDto } from './dto/update-user-password.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Inject(JwtService)
  private jwtService: JwtService;

  @Get('register-captcha')
  async registerCaptcha(@Query('address') address: string) {
    const code = await this.userService.generateCaptcha(address, 'register');
    await this.userService.sendMail(address, code, '注册');

    return '发送成功';
  }

  @Post('register')
  register(@Body() registerUser: RegisterUserDto) {
    return this.userService.register(registerUser);
  }

  @Post('login')
  async userLogin(@Body() loginUser: LoginUserDto) {
    return await this.userService.login(loginUser, false);
  }

  @Post('admin/login')
  async adminLogin(@Body() loginUser: LoginUserDto) {
    return await this.userService.login(loginUser, true);
  }

  @Get('refresh')
  async refreshUserToken(@Query('refreshToken') refreshToken: string) {
    try {
      const data = this.jwtService.verify(refreshToken);
      const user = await this.userService.findUserById(data.userId, false);

      return this.userService.generateToken(user);
    } catch (error) {
      throw new UnauthorizedException('token 失效，请重新登录');
    }
  }

  @Get('admin/refresh')
  async refreshAdminToken(@Query('refreshToken') refreshToken: string) {
    try {
      const data = this.jwtService.verify(refreshToken);
      const user = await this.userService.findUserById(data.userId, true);

      return this.userService.generateToken(user);
    } catch (error) {
      throw new UnauthorizedException('token 失效，请重新登录');
    }
  }

  // 查询当前用户信息
  @Get('info')
  @RequireLogin()
  async info(@UserInfo('userId') userId: number) {
    return await this.userService.findUserDetailById(userId);
  }

  // 获取修改密码验证码
  @Get('update_password/captcha')
  @RequireLogin()
  async updatePasswordCaptcha(@Query('address') address: string) {
    const code = await this.userService.generateCaptcha(
      address,
      'update_password',
    );
    await this.userService.sendMail(address, code, '修改密码');

    return '发送成功';
  }

  // 修改密码
  @Post(['update_password', 'admin/update_password'])
  @RequireLogin()
  async updatePassword(
    @UserInfo('userId') userId: number,
    @Body() updateUserPasswordDto: UpdateUserPasswordDto,
  ) {
    return await this.userService.updatePassword(userId, updateUserPasswordDto);
  }

  // 获取修改信息验证码
  @Get('update/captcha')
  @RequireLogin()
  async updateUserCaptcha(@Query('address') address: string) {
    const code = await this.userService.generateCaptcha(address, 'update');
    await this.userService.sendMail(address, code, '修改信息');

    return '发送成功';
  }

  // 修改信息
  @Post(['update', 'admin/update'])
  @RequireLogin()
  async updateUser(
    @UserInfo('userId') userId: number,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    return await this.userService.updateUser(userId, updateUserDto);
  }

  // 冻结用户
  @Get('freeze')
  @RequireLogin()
  async freezeUser(@Query('id') userId: number) {
    await this.userService.freezeUserById(userId);

    return '冻结成功';
  }

  // 用户列表
  @Get('list')
  @RequireLogin()
  async userList(
    @Query('pageNo', new DefaultValuePipe(1), generateParseIntPipe('pageNo'))
    pageNo: number,
    @Query(
      'pageSize',
      new DefaultValuePipe(2),
      generateParseIntPipe('pageSize'),
    )
    pageSize: number,
    @Query('username') username: string,
    @Query('nickName') nickName: string,
    @Query('email') email: string,
  ) {
    return await this.userService.findUsersByPage(
      pageNo,
      pageSize,
      username,
      nickName,
      email,
    );
  }
}
