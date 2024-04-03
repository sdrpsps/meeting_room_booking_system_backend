interface UserInfo {
  id: number;
  username: string;
  nickName: string;
  email: string;
  avatar: string;
  phoneNumber: string;
  isAdmin: boolean;
  isFrozen: boolean;
  createTime: string;
  roles: string[];
  permissions: string[];
}

export class LoginUserVo {
  userInfo: UserInfo;
  accessToken: string;
  refreshToken: string;
}
