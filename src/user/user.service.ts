import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { RedisService } from 'src/redis/redis.service';
import { md5 } from 'src/utils/md5';
import { Repository } from 'typeorm';
import { LoginUserDto } from './dto/loginUser.dto';
import { RegisterUserDto } from './dto/registerUser.dto';
import { Permission } from './entities/permission.entity';
import { Role } from './entities/role.entity';
import { User } from './entities/user.entity';
import { LoginUserVo } from './vo/loginUser.vo';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UserService {
  private logger = new Logger();

  @Inject(RedisService)
  private redisService: RedisService;

  @Inject(ConfigService)
  private configService: ConfigService;

  @Inject(JwtService)
  private jwtService: JwtService;

  @InjectRepository(User)
  private userRepository: Repository<User>;

  @InjectRepository(Role)
  private roleRepository: Repository<Role>;

  @InjectRepository(Permission)
  private permissionRepository: Repository<Permission>;

  async register(user: RegisterUserDto) {
    const captcha = await this.redisService.get(`captcha_${user.email}`);

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
    const user = await this.userRepository.findOne({
      where: {
        id,
        isAdmin,
      },
      relations: ['roles', 'roles.permissions'],
    });

    return this.generateUserInfo(user);
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

  generateToken(user: Pick<User, 'id' | 'username'>) {
    const accessToken = this.jwtService.sign(
      {
        userId: user.id,
        username: user.username,
      },
      {
        expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRES_TIME'),
      },
    );

    const refreshToken = this.jwtService.sign(
      { userId: user.id },
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
}
