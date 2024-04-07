import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { EmailService } from 'src/email/email.service';
import { RedisService } from 'src/redis/redis.service';
import { md5 } from 'src/utils/md5';
import { Like, Repository } from 'typeorm';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { UpdateUserPasswordDto } from './dto/update-user-password.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Permission } from './entities/permission.entity';
import { Role } from './entities/role.entity';
import { User } from './entities/user.entity';
import { LoginUserVo } from './vo/login-user.vo';
import { UserInfoVo } from './vo/user-info.vo';

@Injectable()
export class UserService {
  private logger = new Logger();

  @Inject(RedisService)
  private redisService: RedisService;

  @Inject(ConfigService)
  private configService: ConfigService;

  @Inject(JwtService)
  private jwtService: JwtService;

  @Inject(EmailService)
  private emailService: EmailService;

  @InjectRepository(User)
  private userRepository: Repository<User>;

  @InjectRepository(Role)
  private roleRepository: Repository<Role>;

  @InjectRepository(Permission)
  private permissionRepository: Repository<Permission>;

  // 生成验证码
  async generateCaptcha(address: string, type: string) {
    const code = Math.random().toString().slice(2, 8);
    await this.redisService.set(`${type}_captcha_${address}`, code, 5 * 60);
    return code;
  }

  // 发送邮件
  async sendMail(address: string, code: string, type: string) {
    await this.emailService.sendMail({
      to: address,
      subject: `${type}验证码`,
      html: `<p>你的${type}验证码是 ${code}</p>`,
    });
  }

  // 注册
  async register(user: RegisterUserDto) {
    const captcha = await this.redisService.get(
      `register_captcha_${user.email}`,
    );

    if (!captcha) {
      throw new HttpException('验证码已过期', HttpStatus.BAD_REQUEST);
    }

    if (user.captcha !== captcha) {
      throw new HttpException('验证码错误', HttpStatus.BAD_REQUEST);
    }

    const foundUser = await this.userRepository.findOneBy({
      username: user.username,
    });

    if (foundUser) {
      throw new HttpException('用户已存在', HttpStatus.BAD_REQUEST);
    }

    const newUser = new User();
    newUser.username = user.username;
    newUser.password = md5(user.password);
    newUser.email = user.email;
    newUser.nickName = user.nickName;

    try {
      await this.userRepository.save(newUser);
      return '注册成功';
    } catch (e) {
      this.logger.error(e, UserService);
      return '注册失败';
    }
  }

  // 登录
  async login(loginUser: LoginUserDto, isAdmin: boolean) {
    const user = await this.userRepository.findOne({
      where: {
        username: loginUser.username,
        isAdmin,
      },
      relations: ['roles', 'roles.permissions'],
    });

    if (!user) {
      throw new HttpException('用户不存在', HttpStatus.BAD_REQUEST);
    }

    if (user.password !== md5(loginUser.password)) {
      throw new HttpException('密码错误', HttpStatus.BAD_REQUEST);
    }

    return this.generateUserResponse(user);
  }

  async findUserById(id: number, isAdmin: boolean) {
    return await this.userRepository.findOne({
      where: {
        id,
        isAdmin,
      },
      relations: ['roles', 'roles.permissions'],
    });
  }

  generatePermission(role: Role[]) {
    return role.reduce((arr, item) => {
      item.permissions.forEach((permission) => {
        if (!arr.includes(permission)) {
          arr.push(permission);
        }
      });
      return arr;
    }, []);
  }

  generateToken(user: User) {
    const accessToken = this.jwtService.sign(
      {
        userId: user.id,
        username: user.username,
        roles: user.roles.map((item) => item.name),
        permissions: this.generatePermission(user.roles),
      },
      {
        expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRES_TIME'),
      },
    );

    const refreshToken = this.jwtService.sign(
      { userId: user.id, username: user.username },
      { expiresIn: this.configService.get('JWT_REFRESH_TOKEN_EXPIRES_TIME') },
    );

    return { accessToken, refreshToken };
  }

  generateUserInfo(user: User) {
    return {
      id: user.id,
      username: user.username,
      nickName: user.nickName,
      email: user.email,
      phoneNumber: user.phoneNumber,
      avatar: user.avatar,
      createTime: user.createTime.toLocaleString(),
      isFrozen: user.isFrozen,
      isAdmin: user.isAdmin,
      roles: user.roles.map((item) => item.name),
      permissions: this.generatePermission(user.roles),
    };
  }

  generateUserResponse(user: User) {
    const vo = new LoginUserVo();
    const { accessToken, refreshToken } = this.generateToken(user);
    vo.userInfo = this.generateUserInfo(user);
    vo.accessToken = accessToken;
    vo.refreshToken = refreshToken;

    return vo;
  }

  async findUserDetailById(userId: number) {
    const user = await this.userRepository.findOneBy({ id: userId });
    const vo = new UserInfoVo();
    vo.id = user.id;
    vo.email = user.email;
    vo.username = user.username;
    vo.avatar = user.avatar;
    vo.phoneNumber = user.phoneNumber;
    vo.nickName = user.nickName;
    vo.createTime = user.createTime;
    vo.isFrozen = user.isFrozen;

    return vo;
  }

  // 修改密码
  async updatePassword(userId: number, dto: UpdateUserPasswordDto) {
    const captcha = await this.redisService.get(
      `update_password_captcha_${dto.email}`,
    );

    if (!captcha) {
      throw new HttpException('验证码已过期', HttpStatus.BAD_REQUEST);
    }

    if (dto.captcha !== captcha) {
      throw new HttpException('验证码错误', HttpStatus.BAD_REQUEST);
    }

    const user = await this.userRepository.findOneBy({ id: userId });

    user.password = md5(dto.password);

    try {
      this.userRepository.save(user);
      return '修改密码成功';
    } catch (error) {
      this.logger.error(error, UserService);
      return '修改密码失败';
    }
  }

  // 修改信息
  async updateUser(userId: number, dto: UpdateUserDto) {
    const captcha = await this.redisService.get(
      `update_user_captcha_${dto.email}`,
    );

    if (!captcha) {
      throw new HttpException('验证码已过期', HttpStatus.BAD_REQUEST);
    }

    if (dto.captcha !== captcha) {
      throw new HttpException('验证码错误', HttpStatus.BAD_REQUEST);
    }

    const user = await this.userRepository.findOneBy({ id: userId });

    if (dto.nickName) user.nickName = dto.nickName;
    if (dto.avatar) user.avatar = dto.avatar;

    try {
      this.userRepository.save(user);
      return '修改信息成功';
    } catch (error) {
      this.logger.error(error, UserService);
      return '修改信息失败';
    }
  }

  // 冻结用户
  async freezeUserById(userId: number) {
    const user = await this.userRepository.findOneBy({ id: userId });

    user.isFrozen = true;

    await this.userRepository.save(user);
  }

  // 用户列表
  async findUsersByPage(
    pageNo: number,
    pageSize: number,
    username: string,
    nickName: string,
    email: string,
  ) {
    const skipCount = (pageNo - 1) * pageSize;

    const condition: Record<string, any> = {};

    if (username) condition.username = Like(`%${username}%`);
    if (nickName) condition.nickName = Like(`%${nickName}%`);
    if (email) condition.email = Like(`%${email}%`);

    const [users, totalCount] = await this.userRepository.findAndCount({
      skip: skipCount,
      take: pageSize,
      select: [
        'id',
        'username',
        'nickName',
        'email',
        'phoneNumber',
        'isFrozen',
        'avatar',
        'createTime',
      ],
      where: condition,
    });

    return { users, totalCount };
  }
}
