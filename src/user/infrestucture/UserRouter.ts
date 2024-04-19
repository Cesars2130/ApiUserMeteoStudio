import express from "express";

import { registerUserController, getUserByEmailController, getUserByIdController, getUsersController, loginUserController } from "./dependencies";
import { verifyToken } from "../../middlewares/autMiddleware";

export const userRouter = express.Router();

userRouter.post(
    "/",
    registerUserController.run.bind(registerUserController)
);

userRouter.post(
     "/login",
     loginUserController.login.bind(loginUserController)
);

userRouter.get(
    "/",
    verifyToken,
    getUsersController.run.bind(getUsersController)
)

userRouter.get(
    "/email/:email",
    verifyToken,
    getUserByEmailController.run.bind(getUserByEmailController)
)

userRouter.get(
    "/:id",
    verifyToken,
    getUserByIdController.run.bind(getUserByIdController)
)
