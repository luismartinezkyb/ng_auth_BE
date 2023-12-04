import { User } from "../entities/auth.entity";

export interface LoginResponse {
  user: User;
  token: string;
}
