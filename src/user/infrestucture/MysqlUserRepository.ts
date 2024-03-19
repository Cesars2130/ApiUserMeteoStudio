import { query } from "../../db/mysql";
import { User } from "../domain/User";
import { UserRepository } from "../domain/userRepository/UserRepository";

export class MysqlUserRepository implements UserRepository {
  async deleteUser(id: number): Promise<User | null> {
    throw new Error("Method not implemented.");
  }

  async registerUser(
    name: string,
    email: string,
    password: string,
    first_last_name: string,
    second_last_name: string,
    birthdate: string,
    type_id: number
  ): Promise<User | null> {
    let user = null;
    const sql =
      "SELECT INTO users (name,email, password, first_last_name , second_last_name , birthdate,  ) VALUES (?,?,?,?,?,?,?)";
    const params: any[] = [
      name,
      email,
      password,
      first_last_name,
      second_last_name,
      birthdate,
      type_id,
    ];
    try {
      const [userR]: any = await query(sql, params);
      user = new User(
        userR.id,
        name,
        email,
        password,
        first_last_name,
        second_last_name,
        birthdate,
        type_id
      );
    } catch (error) {
      user = null;
    } finally {
      return user;
    }
  }

  async getUsers(): Promise<User[] | null> {
    const sql = "SELECT * FROM users";
    try {
      const [data]: any = query(sql, []);
      const dataUsers = Object.values(JSON.parse(JSON.stringify(data)));

      return dataUsers.map(
        (user: any) =>
          new User(
            user.id,
            user.name,
            user.email,
            user.password,
            user.first_last_name,
            user.second_last_name,
            user.birthdate,
            user.type_id
          )
      );
    } catch (error) {
      return null;
    }
  }

  async getById(id: number): Promise<User | null> {
    const sql = "SELECT * FROM user WHERE id=?";
    const params: any[] = [id];

    try {
        const [result]: any = await query(sql, params);
        return new User(
          result[0].id,
          result[0].name,
          result[0].email,
          result[0].password,
          result[0].first_last_name,
          result[0].second_last_name,
          result[0].birthdate,
          result[0].type_id,
        );
      } catch (error) {
        return null;
      }

  }
  async getbyEmail(email: string): Promise<User | null> {
    const sql = "SELECT * FROM user WHERE email=?";
    const params: any[] = [email];

    try {
        const [result]: any = await query(sql, params);
        return new User(
          result[0].id,
          result[0].name,
          result[0].email,
          result[0].password,
          result[0].first_last_name,
          result[0].second_last_name,
          result[0].birthdate,
          result[0].type_id,
        );
      } catch (error) {
        return null;
      }

  }
}
