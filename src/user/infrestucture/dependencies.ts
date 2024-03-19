import { GetUSerByIdUseCase } from "../aplication/GetUserByIdUseCase";
import { GetUserByEmailUseCase } from "../aplication/GetUserByEmailUseCase";
import { GetUsersUseCase } from "../aplication/GetUsersUseCase";
import { RegisterUserUseCase } from "../aplication/RegisterUserUseCase";
import { LoginService } from "../aplication/service/LoginService";

import { MysqlUserRepository } from "./MysqlUserRepository";


import { GetUserByEmailController } from "./controllers/GetUserByEmailController";
import { RegisterUserController } from "./controllers/RegisterUserController";
import { GetUsersController } from "./controllers/GetUsersController";
import { GetUserByIdController } from "./controllers/GetUserByIdController";
import { LoginUserController } from "./controllers/LoginUserController";

export const mysqlUserRepository = new MysqlUserRepository ();


export const registerUserUseCase = new RegisterUserUseCase(mysqlUserRepository);
export const getUserByEmailUseCase = new GetUserByEmailUseCase(mysqlUserRepository);
export const getUserByIdUseCase = new GetUSerByIdUseCase(mysqlUserRepository);
export const getUsersUseCase = new GetUsersUseCase ( mysqlUserRepository);


export const registerUserController = new RegisterUserController(registerUserUseCase);
export const getUserByEmailController = new GetUserByEmailController(getUserByEmailUseCase);
export const getUserByIdController = new GetUserByIdController(getUserByIdUseCase);
export const getUsersController = new GetUsersController(getUsersUseCase);