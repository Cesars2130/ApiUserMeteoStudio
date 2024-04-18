import { Request, Response } from "express";
import { GetUserByEmailUseCase } from "../../aplication/getUserByEmailUseCase";

export class GetUserByEmailController {
  constructor(readonly getUserByEmailUseCase: GetUserByEmailUseCase) {}

  async run(req: Request, res: Response) {
    const email: string = req.params.email;

    try {
      console.log(email);
      const user = await this.getUserByEmailUseCase.run(email);
      if (user) {
        res.status(200).send({
          status: "success",
          data: {
            id: user.id,
            name: user.name,
            email: user.email,
            password: user.password,
            first_last_name: user.first_last_name,
            second_last_name: user.second_last_name,
            birthdate: user.birthdate,
            type_id : user.type_id
          },
        });
      } else {
        res.status(400).send({
          status: "error",
          msn: "Ocurrio algún problema correo",email
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
