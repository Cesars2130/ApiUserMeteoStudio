import { GetUsersUseCase } from "../../aplication/getUsersUseCase";
import { Request, Response } from "express";

export class GetUsersController {
  constructor(readonly getUsersUseCase: GetUsersUseCase) {}
  async run(req: Request, res: Response): Promise<void> {
    try {
      const users = await this.getUsersUseCase.run();
    
      
      if (users) {
        res.status(200).send({
          status: "succes",
          data: users.map((user: any) => {
            return {
              id: user.id,
              name: user.name,
              email: user.email,
              password: user.password,
              first_last_name: user.first_last_name,
              second_last_name: user.second_last_name,
              birthdate: user.birthdate,
              type_id: user.type_id,
            };
          }),
        });
      } else {
        res.status(400).send({
          status: "error",
          msn: "Ocurrio algún problema ",
        });
      }
    } catch (error) {
      res.status(204).send({
        status: "error",
        data: "Ocurrio un error",
        msn: error,
      });
    }
  }
}
